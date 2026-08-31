import { describe, it, expect } from "vitest"
import { extractRouteParams, extractTokenClaims, extractRouteParamValues, matchRouteTemplate, detectBOLA } from "../core/bola"

describe("extractRouteParams", () => {
  it("extracts Express-style params", () => {
    const params = extractRouteParams("/api/users/:userId/orders/:orderId")
    expect(params).toEqual(["userId", "orderId"])
  })

  it("extracts Hono-style params", () => {
    const params = extractRouteParams("/api/users/:userId")
    expect(params).toEqual(["userId"])
  })

  it("returns empty for static routes", () => {
    const params = extractRouteParams("/api/health")
    expect(params).toEqual([])
  })

  it("handles empty path", () => {
    expect(extractRouteParams("")).toEqual([])
  })
})

describe("extractTokenClaims", () => {
  it("extracts claims from valid JWT", () => {
    const token = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcl9pZCI6IjU2NyIsImlkIjoiODkwIn0.signature"
    const claims = extractTokenClaims(token)
    expect(claims.sub).toBe("1234567890")
    expect(claims.user_id).toBe("567")
    expect(claims.id).toBe("890")
  })

  it("returns empty for invalid token", () => {
    const claims = extractTokenClaims("not-a-token")
    expect(claims).toEqual({})
  })

  it("returns empty for token with wrong parts", () => {
    const claims = extractTokenClaims("part1.part2")
    expect(claims).toEqual({})
  })

  it("handles empty token", () => {
    expect(extractTokenClaims("")).toEqual({})
  })
})

describe("detectBOLA", () => {
  it("detects BOLA from route params", () => {
    const result = detectBOLA(
      ["userId"],
      null,
      { sub: "user_123" },
      "/api/users/:userId",
      "GET",
    )
    expect(result).not.toBeNull()
    expect(result!.type).toBe("bola")
    expect(result!.patternId).toBe("bola_param_mismatch")
  })

  it("detects BOLA from body fields", () => {
    const result = detectBOLA(
      [],
      { userId: "user_456" },
      { sub: "user_123" },
      "/api/users",
      "POST",
    )
    expect(result).not.toBeNull()
    expect(result!.type).toBe("bola")
    expect(result!.patternId).toBe("bola_body_mismatch")
  })

  it("returns null when token has no user claim", () => {
    const result = detectBOLA(
      ["userId"],
      null,
      {},
      "/api/users/:userId",
      "GET",
    )
    expect(result).toBeNull()
  })

  it("returns null when no route params and no body", () => {
    const result = detectBOLA(
      [],
      null,
      { sub: "user_123" },
      "/api/health",
      "GET",
    )
    expect(result).toBeNull()
  })

  it("does not flag non-ID route params", () => {
    const result = detectBOLA(
      ["category"],
      null,
      { sub: "user_123" },
      "/api/items/:category",
      "GET",
    )
    expect(result).toBeNull()
  })

  it("passes through when body ID matches token", () => {
    const result = detectBOLA(
      [],
      { userId: "user_123" },
      { sub: "user_123" },
      "/api/users",
      "PUT",
    )
    expect(result).toBeNull()
  })

  it("sets severity to critical for body mismatch", () => {
    const result = detectBOLA(
      [],
      { userId: "user_456" },
      { sub: "user_123" },
      "/api/users",
      "POST",
    )
    expect(result!.severity).toBe("critical")
  })
})

describe("matchRouteTemplate", () => {
  it("matches concrete path to template", () => {
    expect(matchRouteTemplate("/api/users/999", ["/api/users/:userId"])).toBe("/api/users/:userId")
    expect(matchRouteTemplate("/api/users/999", ["/api/users/{user_id}"])).toBe("/api/users/{user_id}")
  })

  it("returns null when no structural match", () => {
    expect(matchRouteTemplate("/api/users/999/orders", ["/api/users/:userId"])).toBeNull()
    expect(matchRouteTemplate("/api/health", ["/api/users/:userId"])).toBeNull()
  })
})

describe("extractRouteParamValues", () => {
  it("extracts param values from concrete path", () => {
    expect(extractRouteParamValues("/api/users/:userId", "/api/users/999")).toEqual({ userId: "999" })
  })

  it("returns empty for mismatched lengths", () => {
    expect(extractRouteParamValues("/api/users/:userId", "/api/users")).toEqual({})
  })
})

describe("detectBOLA with route param values", () => {
  it("flags param value that does not match the authenticated user", () => {
    const result = detectBOLA(
      ["userId"],
      null,
      { sub: "42" },
      "/api/users/:userId",
      "GET",
      { userId: "999" },
    )
    expect(result).not.toBeNull()
    expect(result!.patternId).toBe("bola_param_mismatch")
  })

  it("passes through when param value matches the authenticated user", () => {
    const result = detectBOLA(
      ["userId"],
      null,
      { sub: "42" },
      "/api/users/:userId",
      "GET",
      { userId: "42" },
    )
    expect(result).toBeNull()
  })

  it("ignores values of non-ID params", () => {
    const result = detectBOLA(
      ["category"],
      null,
      { sub: "42" },
      "/api/items/:category",
      "GET",
      { category: "books" },
    )
    expect(result).toBeNull()
  })
})
