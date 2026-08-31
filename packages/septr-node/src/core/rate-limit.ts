import type { RateLimitEntry } from "./types"

/**
 * In-memory sliding window rate limiter. Tracks request counts per key within a configurable time window.
 *
 * Each process maintains its own independent counter. When deployed behind a load balancer
 * with N instances, the effective rate limit is `max * N`. For multi-process deployments:
 * - Use sticky sessions so the same client always hits the same process
 * - Or configure `max` as `desired_limit / num_instances`
 * - A Redis-backed shared limiter is planned for v1.1
 */
export class SlidingWindowRateLimiter {
  private store = new Map<string, RateLimitEntry>()
  readonly max: number
  readonly windowMs: number
  private cleanupTimer: ReturnType<typeof setInterval> | null = null

  constructor(max: number = 60, windowMs: number = 60_000) {
    this.max = max
    this.windowMs = windowMs

    this.cleanupTimer = setInterval(() => {
      this.cleanup()
    }, windowMs)
  }

  private cleanup(): void {
    const now = Date.now()
    for (const [key, entry] of this.store) {
      if (now - entry.windowStart > this.windowMs) {
        this.store.delete(key)
      }
    }
  }

  check(key: string): { allowed: boolean; remaining: number; resetMs: number } {
    const now = Date.now()
    const entry = this.store.get(key)

    if (!entry || now - entry.windowStart > this.windowMs) {
      this.store.set(key, { count: 1, windowStart: now })
      return { allowed: true, remaining: this.max - 1, resetMs: this.windowMs }
    }

    if (entry.count >= this.max) {
      return {
        allowed: false,
        remaining: 0,
        resetMs: this.windowMs - (now - entry.windowStart),
      }
    }

    entry.count++
    return {
      allowed: true,
      remaining: this.max - entry.count,
      resetMs: this.windowMs - (now - entry.windowStart),
    }
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = null
    }
    this.store.clear()
  }

  reset(key?: string): void {
    if (key) {
      this.store.delete(key)
    } else {
      this.store.clear()
    }
  }
}
