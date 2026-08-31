import { describe, it, expect } from "vitest"
import { stripSensitiveData } from "../core/strip"

describe("stripSensitiveData", () => {
  it("redacts sensitive string values", () => {
    const input = "sk-proj-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    const { cleaned, detections } = stripSensitiveData(input)
    expect(cleaned as string).toBe("[REDACTED]")
    expect(detections.length).toBeGreaterThan(0)
  })

  it("redacts sensitive fields by key", () => {
    const input = { name: "John", password: "secret123", email: "john@example.com" }
    const { cleaned, detections } = stripSensitiveData(input)
    expect(cleaned as Record<string, unknown>).toEqual({
      name: "John",
      password: "[REDACTED]",
      email: "john@example.com",
    })
    expect(detections.length).toBe(1)
    expect(detections[0].type).toBe("data_strip")
    expect(detections[0].patternId).toBe("strip_field")
  })

  it("redacts multiple sensitive fields", () => {
    const input = { apiKey: "key123", creditCard: "4111-1111-1111-1111", name: "John" }
    const { cleaned, detections } = stripSensitiveData(input)
    const c = cleaned as Record<string, unknown>
    expect(c.apiKey).toBe("[REDACTED]")
    expect(c.creditCard).toBe("[REDACTED]")
    expect(c.name).toBe("John")
    expect(detections.length).toBe(2)
  })

  it("handles nested objects", () => {
    const input = { user: { password: "secret", profile: { name: "John" } } }
    const { cleaned } = stripSensitiveData(input)
    expect(cleaned as Record<string, unknown>).toEqual({
      user: { password: "[REDACTED]", profile: { name: "John" } },
    })
  })

  it("handles arrays", () => {
    const input = [{ password: "secret1" }, { password: "secret2" }]
    const { cleaned } = stripSensitiveData(input)
    expect(cleaned as Array<Record<string, unknown>>).toEqual([
      { password: "[REDACTED]" },
      { password: "[REDACTED]" },
    ])
  })

  it("redacts secrets in strings within objects", () => {
    const input = { message: "my token is sk-proj-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
    const { cleaned, detections } = stripSensitiveData(input)
    expect((cleaned as Record<string, unknown>).message).toBe("[REDACTED]")
    expect(detections.length).toBeGreaterThan(0)
  })

  it("handles null and undefined", () => {
    expect(stripSensitiveData(null).cleaned as null).toBeNull()
    expect(stripSensitiveData(undefined).cleaned as undefined).toBeUndefined()
  })

  it("handles primitive types", () => {
    expect(stripSensitiveData(42).cleaned as number).toBe(42)
    expect(stripSensitiveData("hello").cleaned as string).toBe("hello")
  })

  it("accepts custom fields", () => {
    const input = { ssn: "123-45-6789", myCustomField: "secret" }
    const { cleaned } = stripSensitiveData(input, ["myCustomField"])
    const c = cleaned as Record<string, unknown>
    expect(c.ssn).toBe("[REDACTED]")
    expect(c.myCustomField).toBe("[REDACTED]")
  })
})

describe("stripSensitiveData entropy behavior", () => {
  it("still redacts confirmed secret patterns under non-sensitive keys", () => {
    const { cleaned, detections } = stripSensitiveData({
      payload: { k: "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" },
    })
    expect((cleaned as any).payload.k).toBe("[REDACTED]")
    expect(detections.some((d) => d.patternId === "secret_stripe_live")).toBe(true)
  })

  it("reports entropy-only values without redacting them", () => {
    const value = "x9F2kQ7vL3pZ8nB4cD6mW1rT"
    const { cleaned, detections } = stripSensitiveData({
      note: `{"apiKey": "${value}"}`,
    })
    expect((cleaned as any).note).toBe(`{"apiKey": "${value}"}`)
    expect(detections.some((d) => d.patternId === "secret_high_entropy")).toBe(true)
  })

  it("redacts real secrets even when an advisory-only key is present", () => {
    const msg = "AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    const { cleaned } = stripSensitiveData({ msg })
    expect((cleaned as any).msg).toBe("[REDACTED]")
  })

  it("does not redact advisory-only keys", () => {
    const msg = "AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI"
    const { cleaned } = stripSensitiveData({ msg })
    expect((cleaned as any).msg).toBe(msg)
  })
})

describe("stripSensitiveData size limits", () => {
  it("caps arrays at 1000 items", () => {
    const input = Array.from({ length: 10_000 }, (_, i) => `item-${i}`)
    const { cleaned } = stripSensitiveData(input)
    expect((cleaned as unknown[]).length).toBe(1000)
  })

  it("skips strings over 10000 chars", () => {
    const longString = "a".repeat(15_000)
    const { cleaned } = stripSensitiveData({ data: longString })
    expect((cleaned as any).data).toBe(longString)
  })

  it("handles deeply nested objects without stack overflow", () => {
    let deep: unknown = "leaf"
    for (let i = 0; i < 20; i++) deep = { level: i, child: deep }
    const { cleaned } = stripSensitiveData(deep)
    expect(cleaned).toBeDefined()
  })

  it("processes a 10k-element array in under 100ms", () => {
    const input = Array.from({ length: 10_000 }, () => ({ name: "test", value: "hello" }))
    const start = performance.now()
    stripSensitiveData(input)
    const elapsed = performance.now() - start
    expect(elapsed).toBeLessThan(100)
  })
})
