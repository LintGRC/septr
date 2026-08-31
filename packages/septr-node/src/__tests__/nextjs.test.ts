import { describe, it, expect, vi, beforeEach } from "vitest"
import { createSeptr, withSeptr } from "../adapters/nextjs"

function makeRequest(overrides?: Record<string, unknown>) {
  return {
    nextUrl: { pathname: "/api/health", searchParams: new URLSearchParams() },
    headers: new Headers(),
    method: "GET",
    json: vi.fn(),
    ...overrides,
  } as any
}

describe("Next.js adapter", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("passes through for safe requests", async () => {
    const middleware = createSeptr({ rateLimit: false, bola: false, secrets: false })
    const req = makeRequest()
    const result = await middleware(req)
    expect(result).toBeUndefined()
  })

  it("blocks rate-limited requests", async () => {
    const middleware = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 2, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    for (let i = 0; i < 2; i++) {
      await middleware(makeRequest({
        headers: new Headers({ "x-forwarded-for": "1.2.3.4" }),
      }))
    }

    const result = await middleware(makeRequest({
      headers: new Headers({ "x-forwarded-for": "1.2.3.4" }),
    }))

    expect(result).toBeDefined()
    expect((result as Response).status).toBe(429)
  })

  it("GETs on auth routes use the general limiter, not the strict auth limiter", async () => {
    const middleware = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 2, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    for (let i = 0; i < 2; i++) {
      const result = await middleware(makeRequest({
        method: "GET",
        nextUrl: { pathname: "/auth/me", searchParams: new URLSearchParams() },
        headers: new Headers({ "x-forwarded-for": "1.2.3.4" }),
      }))
      expect(result).toBeUndefined()
    }

    const result = await middleware(makeRequest({
      method: "GET",
      nextUrl: { pathname: "/auth/me", searchParams: new URLSearchParams() },
      headers: new Headers({ "x-forwarded-for": "1.2.3.4" }),
    }))
    expect((result as Response).status).toBe(429)
  })

  it("POSTs on auth routes keep the strict auth limiter", async () => {
    const middleware = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 100, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    let result: unknown
    for (let i = 0; i < 11; i++) {
      result = await middleware(makeRequest({
        method: "POST",
        nextUrl: { pathname: "/auth/login", searchParams: new URLSearchParams() },
        headers: new Headers({ "x-forwarded-for": "1.2.3.4" }),
      }))
    }
    expect((result as Response).status).toBe(429)
  })

  it("blocks BOLA in strict mode", async () => {
    const middleware = createSeptr({
      bola: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
    })

    const token = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJ1c2VyXzEyMyJ9.signature"
    const req = makeRequest({
      nextUrl: { pathname: "/api/users/:userId", searchParams: new URLSearchParams() },
      headers: new Headers({ authorization: `Bearer ${token}` }),
    })

    const result = await middleware(req)

    expect(result).toBeDefined()
    expect((result as Response).status).toBe(404)
  })

  it("withSeptr wraps handler", async () => {
    const handler = vi.fn().mockResolvedValue(new Response("OK", { status: 200 }))
    const protectedHandler = withSeptr(handler, { rateLimit: false, bola: false, secrets: false })

    const result = await protectedHandler(makeRequest())

    expect(handler).toHaveBeenCalled()
    expect(result.status).toBe(200)
  })
})
