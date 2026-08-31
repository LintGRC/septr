import { describe, it, expect } from "vitest"
import { detectMissingAuth } from "../core/missing-auth"

describe("detectMissingAuth", () => {
  it("flags unprotected routes with no auth header", () => {
    const result = detectMissingAuth("/api/users", "GET", undefined)
    expect(result).not.toBeNull()
    expect(result!.type).toBe("missing_auth")
    expect(result!.severity).toBe("high")
    expect(result!.route).toBe("/api/users")
    expect(result!.method).toBe("GET")
  })

  it("flags unprotected routes with empty auth header", () => {
    const result = detectMissingAuth("/api/projects", "POST", "")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("missing_auth")
  })

  it("flags routes with non-Bearer auth header", () => {
    const result = detectMissingAuth("/api/admin", "DELETE", "Basic dXNlcjpwYXNz")
    expect(result).not.toBeNull()
  })

  it("allows routes with Bearer token", () => {
    const result = detectMissingAuth("/api/users", "GET", "Bearer eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjMifQ")
    expect(result).toBeNull()
  })

  it("allows routes with Bearer token lowercase", () => {
    const result = detectMissingAuth("/api/data", "GET", "bearer some_token")
    expect(result).toBeNull()
  })

  it("allows public routes without auth", () => {
    const publicRoutes = [
      "/auth/login",
      "/login",
      "/register",
      "/signup",
      "/health",
      "/__septr_ping",
      "/favicon.ico",
    ]
    for (const route of publicRoutes) {
      expect(detectMissingAuth(route, "GET", undefined)).toBeNull()
    }
  })

  it("allows public routes case-insensitively", () => {
    expect(detectMissingAuth("/Auth/Login", "GET", undefined)).toBeNull()
    expect(detectMissingAuth("/HEALTH", "GET", undefined)).toBeNull()
  })

  it("flags nested API routes", () => {
    expect(detectMissingAuth("/api/v1/users/123/invoices", "GET", undefined)).not.toBeNull()
    expect(detectMissingAuth("/api/v1/organizations/teams", "POST", undefined)).not.toBeNull()
  })

  it("flags routes with arbitrary methods", () => {
    expect(detectMissingAuth("/api/data", "PATCH", undefined)).not.toBeNull()
    expect(detectMissingAuth("/api/data", "PUT", undefined)).not.toBeNull()
    expect(detectMissingAuth("/api/data", "DELETE", undefined)).not.toBeNull()
  })
})

describe("detectMissingAuth skip rules", () => {
  it("does not flag OPTIONS preflight requests", () => {
    expect(detectMissingAuth("/api/users", "OPTIONS", undefined)).toBeNull()
  })

  it("does not flag HEAD requests", () => {
    expect(detectMissingAuth("/api/users", "HEAD", undefined)).toBeNull()
  })

  it("does not flag static assets", () => {
    expect(detectMissingAuth("/static/main.js", "GET", undefined)).toBeNull()
    expect(detectMissingAuth("/app.css", "GET", undefined)).toBeNull()
  })

  it("still flags real API routes without auth", () => {
    expect(detectMissingAuth("/api/users", "GET", undefined)).not.toBeNull()
  })
})
