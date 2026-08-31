import { describe, it, expect, vi, beforeEach } from "vitest"
import { createSeptr } from "../adapters/hono"

function makeContext(overrides?: Record<string, unknown>) {
  const ctx: Record<string, any> = {
    req: {
      header: vi.fn(),
      method: "GET",
      routePath: "/api/health",
      raw: { body: null },
      json: vi.fn(),
      query: vi.fn(() => ({})),
    },
    res: new Response(null, { status: 200 }),
    json: vi.fn().mockReturnValue(new Response(null, { status: 200 })),
    newResponse: vi.fn((body, status, headers) => new Response(body, { status, headers })),
    ...overrides,
  }
  return ctx as any
}

describe("Hono adapter", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("passes through for safe requests", async () => {
    const middleware = createSeptr({ rateLimit: false, bola: false, secrets: false })
    const ctx = makeContext()
    const next = vi.fn()

    await middleware(ctx, next)

    expect(next).toHaveBeenCalled()
  })

  it("blocks rate-limited requests", async () => {
    const middleware = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 1, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    const ctx = makeContext({
      req: {
        header: vi.fn().mockReturnValue("1.2.3.4"),
        method: "GET",
        routePath: "/api/health",
        raw: { body: null },
        json: vi.fn(),
      },
    })

    await middleware(ctx, vi.fn())
    await middleware(ctx, vi.fn())
    expect(ctx.json).toHaveBeenCalledWith({ error: "Too many requests", details: expect.objectContaining({ type: "rate_limit", severity: "medium" }) }, 429)
  })

  it("GETs on auth routes use the general limiter, not the strict auth limiter", async () => {
    const middleware = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 2, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    for (let i = 0; i < 2; i++) {
      const ctx = makeContext({
        req: {
          header: vi.fn().mockReturnValue("1.2.3.4"),
          method: "GET",
          routePath: "/auth/me",
          raw: { body: null },
          json: vi.fn(),
        },
      })
      await middleware(ctx, vi.fn())
    }

    const ctx = makeContext({
      req: {
        header: vi.fn().mockReturnValue("1.2.3.4"),
        method: "GET",
        routePath: "/auth/me",
        raw: { body: null },
        json: vi.fn(),
      },
    })
    await middleware(ctx, vi.fn())
    expect(ctx.json).toHaveBeenCalledWith(expect.objectContaining({ error: "Too many requests" }), 429)
  })

  it("POSTs on auth routes keep the strict auth limiter", async () => {
    const middleware = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 100, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    let ctx: any
    for (let i = 0; i < 11; i++) {
      ctx = makeContext({
        req: {
          header: vi.fn().mockReturnValue("1.2.3.4"),
          method: "POST",
          routePath: "/auth/login",
          raw: { body: null },
          json: vi.fn(),
        },
      })
      await middleware(ctx, vi.fn())
    }
    expect(ctx.json).toHaveBeenCalledWith(expect.objectContaining({ error: "Too many requests" }), 429)
  })

  it("blocks BOLA in strict mode", async () => {
    const middleware = createSeptr({
      bola: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
    })

    const token = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJ1c2VyXzEyMyJ9.signature"
    const ctx = makeContext({
      req: {
        header: vi.fn((name: string) => name === "authorization" ? `Bearer ${token}` : undefined),
        method: "GET",
        routePath: "/api/users/:userId",
        raw: { body: null },
        json: vi.fn(),
      },
    })

    await middleware(ctx, vi.fn())

    expect(ctx.newResponse).toHaveBeenCalledWith(null, 404)
  })

  it("sanitizes input", async () => {
    const middleware = createSeptr({
      inputSanitize: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
      bola: false,
    })

    const ctx = makeContext({
      req: {
        header: vi.fn(),
        method: "POST",
        routePath: "/api/users",
        raw: { body: null },
        json: vi.fn().mockResolvedValue({ name: "1 UNION SELECT * FROM users" }),
      },
    })

    await middleware(ctx, vi.fn())

    expect(ctx.json).toHaveBeenCalledWith(
      { error: "Request blocked by Septr security filter", details: expect.objectContaining({ type: "input_sanitize", severity: "high" }) },
      400,
    )
  })

  it("blocks cross-tenant data leaks in responses", async () => {
    const JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + "eyJ0ZW5hbnRfaWQiOiIxMjMiLCJz" + "dWIiOiI0MiJ9."
    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id", blockOnMismatch: true },
    })

    const ctx = makeContext({
      req: {
        header: vi.fn((name: string) => name === "authorization" ? `Bearer ${JWT}` : undefined),
        method: "GET",
        routePath: "/api/data",
        raw: { body: null },
        json: vi.fn(),
      },
      res: new Response(JSON.stringify({ tenant_id: "456", name: "Cross-Tenant" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    })

    await middleware(ctx, vi.fn())

    expect(ctx.res.status).toBe(403)
    const body = await ctx.res.json()
    expect(body.error).toContain("Cross-tenant")
  })

  it("passes through when tenant matches in response", async () => {
    const JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + "eyJ0ZW5hbnRfaWQiOiIxMjMiLCJz" + "dWIiOiI0MiJ9."
    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id", blockOnMismatch: true },
    })

    const ctx = makeContext({
      req: {
        header: vi.fn((name: string) => name === "authorization" ? `Bearer ${JWT}` : undefined),
        method: "GET",
        routePath: "/api/data",
        raw: { body: null },
        json: vi.fn(),
      },
      res: new Response(JSON.stringify({ tenant_id: "123", name: "Safe" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    })

    await middleware(ctx, vi.fn())

    expect(ctx.res.status).toBe(200)
  })
})
