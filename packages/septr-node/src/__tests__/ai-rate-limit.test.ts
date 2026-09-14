import { describe, it, expect } from "vitest"
import { hasRateLimitHint } from "../core/ai-rate-limit"

describe("hasRateLimitHint", () => {
  it("detects quota and 429 markers", () => {
    expect(hasRateLimitHint('{"error": {"code": "insufficient_quota"}}')).toBe(true)
    expect(hasRateLimitHint('{"error": "429 Too Many Requests"}')).toBe(true)
  })

  it("ignores plain payloads", () => {
    expect(hasRateLimitHint('{"report": "quarterly numbers", "total": 42}')).toBe(false)
  })
})
