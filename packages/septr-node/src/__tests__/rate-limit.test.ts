import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import { SlidingWindowRateLimiter } from "../core/rate-limit"

describe("SlidingWindowRateLimiter", () => {
  let limiter: SlidingWindowRateLimiter

  beforeEach(() => {
    vi.useFakeTimers()
    limiter = new SlidingWindowRateLimiter(5, 1000)
  })

  afterEach(() => {
    limiter.destroy()
    vi.useRealTimers()
  })

  it("allows requests within limit", () => {
    for (let i = 0; i < 5; i++) {
      const result = limiter.check("test-key")
      expect(result.allowed).toBe(true)
    }
  })

  it("blocks requests exceeding limit", () => {
    for (let i = 0; i < 5; i++) {
      limiter.check("test-key")
    }
    const result = limiter.check("test-key")
    expect(result.allowed).toBe(false)
    expect(result.remaining).toBe(0)
  })

  it("resets after window expires", () => {
    for (let i = 0; i < 5; i++) {
      limiter.check("test-key")
    }
    vi.advanceTimersByTime(1001)
    const result = limiter.check("test-key")
    expect(result.allowed).toBe(true)
  })

  it("tracks remaining count", () => {
    const r1 = limiter.check("test-key")
    expect(r1.remaining).toBe(4)

    const r2 = limiter.check("test-key")
    expect(r2.remaining).toBe(3)
  })

  it("isolates different keys", () => {
    limiter.check("key-a")
    limiter.check("key-a")
    limiter.check("key-b")

    expect(limiter.check("key-a").remaining).toBe(2)
    expect(limiter.check("key-b").remaining).toBe(3)
  })

  it("resets a specific key", () => {
    limiter.check("key-a")
    limiter.check("key-a")
    limiter.reset("key-a")
    const result = limiter.check("key-a")
    expect(result.remaining).toBe(4)
  })

  it("resets all keys", () => {
    limiter.check("key-a")
    limiter.check("key-b")
    limiter.reset()
    expect(limiter.check("key-a").remaining).toBe(4)
    expect(limiter.check("key-b").remaining).toBe(4)
  })

  it("returns resetMs", () => {
    const result = limiter.check("test-key")
    expect(result.resetMs).toBeGreaterThan(0)
  })
})
