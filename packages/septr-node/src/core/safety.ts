/**
 * Fail-open safety primitives.
 *
 * Septr's contract: it must never break or measurably slow the host app.
 * Detection engines run behind a guard that catches errors, enforces a
 * per-call time budget, and trips a per-engine circuit breaker after repeated
 * failures so a broken engine is skipped for the rest of the process.
 *
 * `SEPTR_DISABLED=true` (or `disabled: true` in the config) is an emergency
 * kill switch: the middleware passes every request through untouched while
 * the SDK stays installed.
 */

export interface SeptrSafetyOptions {
  failureThreshold?: number
  budgetMs?: number
  onDegraded?: (engine: string, reason: string) => void
}

export const DEFAULT_FAILURE_THRESHOLD = 3
export const DEFAULT_ENGINE_BUDGET_MS = 50

export function killSwitchEngaged(config?: { disabled?: boolean }): boolean {
  if (config?.disabled === true) return true
  const raw =
    typeof process !== "undefined" ? process.env?.SEPTR_DISABLED ?? "" : ""
  const value = raw.trim().toLowerCase()
  return value === "1" || value === "true" || value === "yes" || value === "on"
}

export class EngineGuard {
  private failures = new Map<string, number>()
  private open = new Set<string>()
  private reported = new Set<string>()
  private threshold: number
  private budgetMs: number
  private onDegraded?: (engine: string, reason: string) => void

  constructor(opts: SeptrSafetyOptions = {}) {
    this.threshold = Math.max(1, opts.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD)
    this.budgetMs = Math.max(0, opts.budgetMs ?? DEFAULT_ENGINE_BUDGET_MS)
    this.onDegraded = opts.onDegraded
  }

  isOpen(engine: string): boolean {
    return this.open.has(engine)
  }

  /** Run fn under the guard; return fallback on skip/failure. */
  run<T>(engine: string, fn: () => T, fallback: T): T {
    if (this.open.has(engine)) return fallback
    const start = Date.now()
    let result: T
    try {
      result = fn()
    } catch (err) {
      const message =
        err instanceof Error ? `${err.name}: ${err.message}` : String(err)
      this.recordFailure(engine, message)
      return fallback
    }
    if (this.budgetMs > 0) {
      const elapsed = Date.now() - start
      if (elapsed > this.budgetMs) {
        this.recordFailure(engine, `took ${elapsed}ms (budget ${this.budgetMs}ms)`)
      }
    }
    return result
  }

  private recordFailure(engine: string, reason: string): void {
    if (this.open.has(engine)) return
    const count = (this.failures.get(engine) ?? 0) + 1
    this.failures.set(engine, count)
    let report = false
    if (count >= this.threshold) {
      this.open.add(engine)
      if (!this.reported.has(engine)) {
        this.reported.add(engine)
        report = true
      }
    }
    // eslint-disable-next-line no-console
    console.warn(`[septr] engine "${engine}" failed (${reason})${this.open.has(engine) ? " — disabled for this process" : ""}`)
    if (report && this.onDegraded) {
      try {
        this.onDegraded(engine, reason)
      } catch {
        // reporting is best-effort
      }
    }
  }

  degradedEngines(): string[] {
    return [...this.open].sort()
  }
}

/** Run fn, returning fallback on any exception. No breaker. */
export function safeCall<T>(fn: () => T, fallback: T): T {
  try {
    return fn()
  } catch {
    return fallback
  }
}
