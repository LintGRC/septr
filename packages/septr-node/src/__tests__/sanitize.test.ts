import { describe, it, expect } from "vitest"
import { detectSQLi, detectXSS, detectNoSQLi, sanitizeInput, sanitizeQuery } from "../core/sanitize"

describe("detectSQLi", () => {
  it("detects UNION SELECT", () => {
    const result = detectSQLi("1 UNION SELECT * FROM users")
    expect(result.length).toBeGreaterThan(0)
    expect(result[0].patternId).toBe("sqli_union")
  })

  it("detects OR 1=1", () => {
    const result = detectSQLi("' OR 1=1 --")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects DROP TABLE", () => {
    const result = detectSQLi("DROP TABLE users")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects DELETE FROM", () => {
    const result = detectSQLi("DELETE FROM users WHERE id=1")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects SQL comments", () => {
    const result = detectSQLi("admin'--")
    expect(result.length).toBeGreaterThan(0)
  })

  it("returns empty for safe strings", () => {
    const result = detectSQLi("hello world")
    expect(result.length).toBe(0)
  })

  it("is case-insensitive", () => {
    const result = detectSQLi("union select * from users")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects multiple patterns in one string", () => {
    const result = detectSQLi("1 UNION SELECT *; DROP TABLE users")
    expect(result.length).toBeGreaterThanOrEqual(2)
  })
})

describe("detectXSS", () => {
  it("detects script tags", () => {
    const result = detectXSS("<script>alert('xss')</script>")
    expect(result.length).toBeGreaterThan(0)
    expect(result[0].patternId).toBe("xss_script_tag")
  })

  it("detects onerror handlers", () => {
    const result = detectXSS("<img src=x onerror=alert(1)>")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects javascript: URLs", () => {
    const result = detectXSS("<a href='javascript:alert(1)'>click</a>")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects eval()", () => {
    const result = detectXSS("eval(document.cookie)")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects iframe injection", () => {
    const result = detectXSS("<iframe src='http://evil.com'></iframe>")
    expect(result.length).toBeGreaterThan(0)
  })

  it("returns empty for safe strings", () => {
    const result = detectXSS("hello world")
    expect(result.length).toBe(0)
  })
})

describe("sanitizeInput", () => {
  it("detects SQLi in shallow string", () => {
    const result = sanitizeInput("1 UNION SELECT * FROM users")
    expect(result.block).toBe(true)
    expect(result.detections.length).toBeGreaterThan(0)
  })

  it("detects XSS in nested object", () => {
    const result = sanitizeInput({ name: "<script>alert(1)</script>", age: 30 })
    expect(result.block).toBe(true)
    expect(result.detections.length).toBeGreaterThan(0)
  })

  it("detects threats in arrays", () => {
    const result = sanitizeInput(["safe", "DROP TABLE users", "<img onerror=...>"])
    expect(result.block).toBe(true)
    expect(result.detections.length).toBeGreaterThanOrEqual(2)
  })

  it("passes safe payloads", () => {
    const result = sanitizeInput({ name: "John", age: 30, email: "john@example.com" })
    expect(result.block).toBe(false)
    expect(result.detections.length).toBe(0)
  })

  it("handles null and undefined", () => {
    expect(sanitizeInput(null).block).toBe(false)
    expect(sanitizeInput(undefined).block).toBe(false)
  })

  it("handles deeply nested objects", () => {
    const result = sanitizeInput({
      user: {
        profile: {
          bio: "<script>alert(1)</script>",
        },
      },
    })
    expect(result.block).toBe(true)
  })
})

describe("sanitizeQuery", () => {
  it("detects SQLi in query param value", () => {
    const result = sanitizeQuery({ q: "1 UNION SELECT * FROM users" })
    expect(result.block).toBe(true)
  })

  it("detects XSS in query param value", () => {
    const result = sanitizeQuery({ name: "<script>alert(1)</script>" })
    expect(result.block).toBe(true)
  })

  it("handles array query params", () => {
    const result = sanitizeQuery({ ids: ["safe", "DROP TABLE users"] })
    expect(result.block).toBe(true)
    expect(result.detections.length).toBeGreaterThanOrEqual(1)
  })

  it("passes safe query params", () => {
    const result = sanitizeQuery({ q: "hello", page: "1" })
    expect(result.block).toBe(false)
    expect(result.detections.length).toBe(0)
  })

  it("handles empty query", () => {
    const result = sanitizeQuery({})
    expect(result.block).toBe(false)
  })
})

describe("detectNoSQLi", () => {
  it("detects $ne operator", () => {
    const events = detectNoSQLi('{"$ne": null}')
    expect(events.some((e) => e.patternId === "nosqli_ne")).toBe(true)
    expect(events[0].severity).toBe("high")
  })

  it("detects $where and $gt", () => {
    const events = detectNoSQLi('{"$where": "sleep(5000)", "price": {"$gt": 0}}')
    const ids = new Set(events.map((e) => e.patternId))
    expect(ids.has("nosqli_where")).toBe(true)
    expect(ids.has("nosqli_gt")).toBe(true)
  })

  it("sanitizeInput catches NoSQLi in bodies", () => {
    const { block, detections } = sanitizeInput({ username: { $ne: null }, password: "x" })
    expect(block).toBe(true)
    expect(detections.some((d) => d.patternId === "nosqli_ne")).toBe(true)
  })

  it("does not flag clean input", () => {
    const { block, detections } = sanitizeInput({ q: "hello world", n: 5 })
    expect(block).toBe(false)
    expect(detections).toEqual([])
  })
})

describe("SQLi obfuscation normalization", () => {
  it("detects comment-obfuscated OR", () => {
    const events = detectSQLi("x' OR/**/1=1--")
    expect(events.some((e) => e.patternId === "sqli_or_1_1")).toBe(true)
  })

  it("detects hex-encoded UNION SELECT", () => {
    // 0x554E494F4E2053454C454354 = "UNION SELECT"
    const events = detectSQLi("x' AND 0x554E494F4E2053454C454354--")
    expect(events.some((e) => e.patternId === "sqli_union")).toBe(true)
  })

  it("detects char() UNION SELECT", () => {
    // char(85,78,73,79,78,32,83,69,76,69,67,84) = "UNION SELECT"
    const events = detectSQLi("x' AND char(85,78,73,79,78,32,83,69,76,69,67,84)--")
    expect(events.some((e) => e.patternId === "sqli_union")).toBe(true)
  })

  it("detects URL-encoded OR 1=1", () => {
    const events = detectSQLi("x%27%20OR%201%3D1--")
    expect(events.some((e) => e.patternId === "sqli_or_1_1")).toBe(true)
  })

  it("does not flag benign text", () => {
    expect(detectSQLi("hello world")).toEqual([])
    expect(detectSQLi("https://example.com/path?q=search")).toEqual([])
    expect(detectSQLi("color code #ff0000 is red")).toEqual([])
  })
})
