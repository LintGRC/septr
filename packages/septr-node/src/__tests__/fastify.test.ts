import { describe, it, expect, vi, beforeEach } from "vitest"
import { createSeptr } from "../adapters/fastify"

function makeRequest(overrides?: Record<string, unknown>) {
  return {
    method: "GET",
    url: "/api/health",
    routeOptions: { url: "/api/health" },
    headers: {},
    body: undefined,
    ...overrides,
  } as any
}

function makeReply() {
  return {
    statusCode: 200,
    code: vi.fn().mockReturnThis(),
    header: vi.fn(),
    send: vi.fn(),
  } as any
}

function callPreSerialization(plugin: any, request: any, reply: any, payload: unknown) {
  return new Promise((resolve, reject) => {
    plugin.preSerialization(request, reply, payload, (err?: Error | null, result?: unknown) => {
      if (err) reject(err)
      else resolve(result)
    })
  })
}

describe("Fastify adapter", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("passes through for safe requests", async () => {
    const plugin = createSeptr({ rateLimit: false, bola: false, secrets: false })
    await plugin.onRequest(makeRequest(), makeReply())
  })

  it("blocks rate-limited requests", async () => {
    const plugin = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 1, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    const req = makeRequest({ headers: { "x-forwarded-for": "1.2.3.4" } })
    await plugin.onRequest(req, makeReply())

    const reply = makeReply()
    await plugin.onRequest(req, reply)

    expect(reply.code).toHaveBeenCalledWith(429)
    expect(reply.send).toHaveBeenCalledWith({ error: "Too many requests", details: expect.objectContaining({ type: "rate_limit", severity: "medium" }) })
  })

  it("GETs on auth routes use the general limiter, not the strict auth limiter", async () => {
    const plugin = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 2, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    for (let i = 0; i < 2; i++) {
      await plugin.onRequest(makeRequest({ method: "GET", url: "/auth/me", headers: { "x-forwarded-for": "1.2.3.4" } }), makeReply())
    }

    const reply = makeReply()
    await plugin.onRequest(makeRequest({ method: "GET", url: "/auth/me", headers: { "x-forwarded-for": "1.2.3.4" } }), reply)

    expect(reply.code).toHaveBeenCalledWith(429)
  })

  it("POSTs on auth routes keep the strict auth limiter", async () => {
    const plugin = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 100, windowMs: 60000 },
      bola: false,
      secrets: false,
    })

    let reply: any
    for (let i = 0; i < 11; i++) {
      reply = makeReply()
      await plugin.onRequest(makeRequest({ method: "POST", url: "/auth/login", headers: { "x-forwarded-for": "1.2.3.4" } }), reply)
    }
    expect(reply.code).toHaveBeenCalledWith(429)
  })

  it("blocks BOLA in strict mode", async () => {
    const plugin = createSeptr({
      bola: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
    })

    const token = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJ1c2VyXzEyMyJ9.signature"
    const req = makeRequest({
      url: "/api/users/:userId",
      routeOptions: { url: "/api/users/:userId" },
      headers: { authorization: `Bearer ${token}` },
    })

    const reply = makeReply()
    await plugin.onRequest(req, reply)

    expect(reply.code).toHaveBeenCalledWith(404)
    expect(reply.send).toHaveBeenCalled()
  })

  it("strips secrets in preSerialization", async () => {
    const plugin = createSeptr({
      secrets: true,
      rateLimit: false,
      bola: false,
    })

    const payload = { name: "John", password: "secret123" }
    const result = await callPreSerialization(plugin, makeRequest(), makeReply(), payload)

    expect(result).toEqual({ name: "John", password: "[REDACTED]" })
  })

  it("passes through payload when secrets is disabled", async () => {
    const plugin = createSeptr({
      secrets: false,
      rateLimit: false,
      bola: false,
    })

    const payload = { password: "secret" }
    const result = await callPreSerialization(plugin, makeRequest(), makeReply(), payload)

    expect(result).toBe(payload)
  })

  it("sanitizes input on POST in preHandler", async () => {
    const plugin = createSeptr({
      inputSanitize: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
      bola: false,
    })

    const req = makeRequest({
      method: "POST",
      body: { name: "1 UNION SELECT * FROM users" },
    })
    const reply = makeReply()
    await plugin.preHandler(req, reply)

    expect(reply.code).toHaveBeenCalledWith(400)
    expect(reply.send).toHaveBeenCalledWith({ error: "Request blocked by Septr security filter", details: expect.objectContaining({ type: "input_sanitize", severity: "high" }) })
  })

  it("blocks cross-tenant data leaks in preSerialization", async () => {
    const JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + "eyJ0ZW5hbnRfaWQiOiIxMjMiLCJz" + "dWIiOiI0MiJ9."
    const plugin = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id", blockOnMismatch: true },
    })

    const req = makeRequest({
      headers: { authorization: `Bearer ${JWT}` },
    })
    const reply = makeReply()

    await plugin.onRequest(req, reply)

    const result = await callPreSerialization(plugin, req, reply, { tenant_id: "456", name: "Cross-Tenant" })

    expect(reply.code).toHaveBeenCalledWith(403)
    expect(result).toEqual({
      error: "Cross-tenant data leak detected by Septr",
      details: expect.objectContaining({ type: "cross_tenant_leak", severity: "high" }),
    })
  })

  it("passes through when tenant matches in preSerialization", async () => {
    const JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + "eyJ0ZW5hbnRfaWQiOiIxMjMiLCJz" + "dWIiOiI0MiJ9."
    const plugin = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id", blockOnMismatch: true },
    })

    const req = makeRequest({
      headers: { authorization: `Bearer ${JWT}` },
    })
    const reply = makeReply()

    await plugin.onRequest(req, reply)

    const payload = { tenant_id: "123", name: "Safe" }
    const result = await callPreSerialization(plugin, req, reply, payload)

    expect(reply.code).not.toHaveBeenCalledWith(403)
    expect(result).toBe(payload)
  })
})
