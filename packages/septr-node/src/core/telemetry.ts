import type { DetectionEvent, TelemetryPayload, SeptrConfig } from "./types"

// Package identity. The version is injected at build time by tsup (`define`);
// the fallback keeps vitest / source layouts working without the define.
const PACKAGE_NAME = "septr"
const PACKAGE_VERSION: string =
  typeof __SEPTR_VERSION__ === "undefined" ? "0.1.0" : __SEPTR_VERSION__

const DEFAULT_FLUSH_INTERVAL_MS = 30_000
const MAX_BATCH_SIZE = 50
const MAX_BUFFER_SIZE = 500
const MAX_RETRY_INTERVAL_MS = 300_000
const HANDSHAKE_PATH = "/handshake"

function telemetryBaseUrl(config: SeptrConfig): string {
  const url = config.telemetryUrl || "https://api.septr.com/v1/events"
  return url.endsWith("/events") ? url.slice(0, -"/events".length) : url
}

/** POST /handshake to verify the API key and fetch project identity. Never throws. */
export async function sendHandshake(config: SeptrConfig): Promise<boolean> {
  const apiKey = config.apiKey || process.env.SEPTR_API_KEY || process.env.VS_API_KEY || ""
  if (!apiKey || typeof fetch !== "function") return false
  const url = `${telemetryBaseUrl(config).replace(/\/+$/, "")}${HANDSHAKE_PATH}`
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        runtime: config.framework || "",
        package: PACKAGE_NAME,
        version: PACKAGE_VERSION,
        environment: process.env.NODE_ENV || "production",
      }),
      signal: AbortSignal.timeout(5_000),
    })
    if (!response.ok) return false
    const data = (await response.json()) as { status?: string; project?: { name?: string } }
    if (data.status !== "connected") return false
    console.log(
      `[septr] Connected to project '${data.project?.name || ""}' (id=${config.projectId || ""}) — handshake OK`,
    )
    return true
  } catch {
    return false
  }
}

/** Per-instance telemetry manager that buffers detection events and flushes them in batches to the Septr API. Supports exponential backoff on failure. */
export class TelemetryManager {
  private buffer: DetectionEvent[] = []
  private flushTimer: ReturnType<typeof setInterval> | null = null
  private projectId: string
  private config: SeptrConfig
  private currentFlushInterval: number
  private beforeExitHandler: (() => void) | null = null
  destroyed = false

  constructor(config: SeptrConfig, projectId: string) {
    this.config = config
    this.projectId = projectId
    this.currentFlushInterval = config.telemetryUrl === "false" ? 0 : DEFAULT_FLUSH_INTERVAL_MS

    if (this.currentFlushInterval > 0) {
      this.flushTimer = setInterval(() => {
        this.flush()
      }, this.currentFlushInterval)
    }

    if (typeof process !== "undefined" && process.on) {
      this.beforeExitHandler = () => {
        if (!this.destroyed && this.buffer.length > 0) {
          this.flush()
        }
      }
      process.on("beforeExit", this.beforeExitHandler)
    }
  }

  emit(event: DetectionEvent): void {
    if (this.config.telemetry === false || this.destroyed) return

    this.buffer.push(event)

    if (this.buffer.length >= MAX_BUFFER_SIZE) {
      const dropped = this.buffer.length - MAX_BUFFER_SIZE
      this.buffer.splice(0, dropped)
    }

    if (this.buffer.length >= MAX_BATCH_SIZE) {
      this.flush()
    }
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0 || !this.projectId || this.destroyed) return

    const batch = this.buffer.splice(0, MAX_BATCH_SIZE)

    try {
      await this.sendBatch(batch)
      this.currentFlushInterval = DEFAULT_FLUSH_INTERVAL_MS
    } catch {
      this.buffer.unshift(...batch)
      this.currentFlushInterval = Math.min(
        this.currentFlushInterval * 2,
        MAX_RETRY_INTERVAL_MS,
      )
      if (this.flushTimer) {
        clearInterval(this.flushTimer)
      }
      this.flushTimer = setInterval(() => {
        this.flush()
      }, this.currentFlushInterval)
    }
  }

  private async sendBatch(batch: DetectionEvent[]): Promise<void> {
    const url = this.config.telemetryUrl || "https://api.septr.com/v1/events"

    const payload: TelemetryPayload = {
      events: batch.map(({ timestamp: _, ...rest }) => rest),
      projectId: this.projectId,
      packageName: PACKAGE_NAME,
      packageVersion: PACKAGE_VERSION,
      environment:
        typeof process !== "undefined" && process.env?.NODE_ENV || "production",
      schemaVersion: "0.1",
      framework: this.config.framework || "",
    }

    if (typeof fetch === "function") {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": `Septr-Telemetry/${PACKAGE_VERSION}`,
          ...(this.config.apiKey
            ? { Authorization: `Bearer ${this.config.apiKey}` }
            : {}),
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(5_000),
      })
      if (!response.ok) {
        throw new Error(`Telemetry API responded with ${response.status}`)
      }
    }
  }

  destroy(): void {
    this.destroyed = true
    if (this.flushTimer) {
      clearInterval(this.flushTimer)
      this.flushTimer = null
    }
    if (this.beforeExitHandler && typeof process !== "undefined" && process.off) {
      process.off("beforeExit", this.beforeExitHandler)
      this.beforeExitHandler = null
    }
  }

  sendVerified(runtimeInfo?: Record<string, unknown>): void {
    this.emit({
      type: "system",
      severity: "info",
      patternId: "self_test",
      description: `Self-test passed${runtimeInfo ? ` (${JSON.stringify(runtimeInfo)})` : ""}`,
      route: "__verified__",
      timestamp: Date.now(),
    })
  }

  sendTestResults(results: { engine: string; passed: boolean }[], runtimeInfo?: Record<string, unknown>): void {
    for (const { engine, passed } of results) {
      this.emit({
        type: "system",
        severity: passed ? "info" : "high",
        patternId: `test_${engine}`,
        description: engine,
        route: "__test_result__",
        timestamp: Date.now(),
      })
    }
    this.sendVerified(runtimeInfo)
    void this.flush()
  }

  get queueSize(): number {
    return this.buffer.length
  }
}

let defaultManager: TelemetryManager | null = null

/** Initialize the singleton telemetry manager. Destroys any previous instance. */
export function initTelemetry(config: SeptrConfig, id: string, runtime?: string): void {
  if (defaultManager) {
    defaultManager.destroy()
  }
  if (runtime) config.framework = config.framework || runtime
  // Fail-loud: warn once when the SEPTR_API_KEY in this process environment
  // differs from the one in a local .env file (shell / launcher export
  // footgun — dotenv loads won't override an already-set env var). Runs even
  // when the app injects the env key into the middleware config explicitly.
  // Node-only: dynamic import keeps fs/path out of edge-runtime bundles.
  if (typeof process !== "undefined" && process.versions?.node) {
    void import("./telemetry.node.js")
      .then((m) => m.nodeTelemetryBootstrap())
      .catch(() => {})
  }
  defaultManager = new TelemetryManager(config, id)

  // Handshake: verify the key and report runtime/version to the backend.
  // Retries in the background on failure (self-dogfooding apps handshake
  // before their own port is listening).
  void sendHandshake(config).then((ok) => {
    if (!ok && config.telemetry !== false) startHandshakeRetry(config)
  })
}

function startHandshakeRetry(config: SeptrConfig, intervalMs = 10_000): void {
  let backoff = intervalMs
  const tick = async (): Promise<void> => {
    if (defaultManager?.destroyed) return
    if (await sendHandshake(config)) return
    backoff = Math.min(backoff * 2, 60_000)
    const timer = setTimeout(() => void tick(), backoff)
    timer.unref?.()
  }
  const timer = setTimeout(() => void tick(), backoff)
  timer.unref?.()
}

/** Queue a detection event for telemetry. Respects the `telemetry` config flag.
 *
 * **Privacy guarantee:** Telemetry is metadata plus a short diagnostic
 * description. Only the event type, severity, pattern ID, route, method,
 * timestamp, and description are transmitted; the description may include
 * resource identifiers (record/tenant IDs) needed to triage the finding.
 * Request/response bodies and secret values are never sent over the network. */
export function emitEvent(event: DetectionEvent, config: SeptrConfig): void {
  if (config.telemetry === false) return

  if (defaultManager && !defaultManager.destroyed) {
    defaultManager.emit(event)
  }
}

/** Send a `__verified__` telemetry event confirming Septr's self-test passed. */
export function sendVerified(runtimeInfo?: Record<string, unknown>): void {
  if (defaultManager && !defaultManager.destroyed) {
    defaultManager.sendVerified(runtimeInfo)
  }
}

/**
 * Send per-engine test results to the backend. Emits one event per engine (with `route: "__test_result__"`)
 * followed by a `__verified__` event.
 */
export function sendTestResults(results: { engine: string; passed: boolean }[], runtimeInfo?: Record<string, unknown>): void {
  if (defaultManager && !defaultManager.destroyed) {
    defaultManager.sendTestResults(results, runtimeInfo)
  }
}

/** Force-flush any buffered telemetry events. Returns a promise that resolves when the flush completes. */
export function flushSync(_telemetryUrl?: string): Promise<void> {
  if (defaultManager) {
    return defaultManager.flush()
  }
  return Promise.resolve()
}

/** Destroy the singleton telemetry manager and clean up all timers and listeners. */
export function destroyTelemetry(): void {
  if (defaultManager) {
    defaultManager.destroy()
    defaultManager = null
  }
}
