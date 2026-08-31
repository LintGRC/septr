import { describe, it, expect } from "vitest"
import { detectMissingSecurityHeaders } from "../core/headers"

describe("detectMissingSecurityHeaders", () => {
  it("reports all standard missing headers", () => {
    const events = detectMissingSecurityHeaders(new Headers({ "content-type": "application/json" }))
    const descriptions = events.map((e) => e.description)
    expect(events.length).toBe(5)
    expect(descriptions.some((d) => d.includes("Content-Security-Policy"))).toBe(true)
    expect(descriptions.some((d) => d.includes("Strict-Transport-Security"))).toBe(true)
    expect(descriptions.some((d) => d.includes("X-Frame-Options"))).toBe(true)
  })

  it("returns no events when all headers are present", () => {
    const headers = new Headers({
      "Content-Security-Policy": "default-src 'self'",
      "Strict-Transport-Security": "max-age=31536000",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    })
    expect(detectMissingSecurityHeaders(headers)).toEqual([])
  })

  it("handles plain object headers", () => {
    const events = detectMissingSecurityHeaders({ "x-powered-by": "express" })
    expect(events.length).toBe(5)
  })

  it("is case-insensitive", () => {
    const events = detectMissingSecurityHeaders(new Headers({ "x-frame-options": "DENY" }))
    expect(events.some((e) => e.description.includes("X-Frame-Options"))).toBe(false)
  })
})
