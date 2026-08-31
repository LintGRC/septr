import { describe, it, expect, vi, beforeEach } from "vitest"
import { createSeptr } from "../adapters/express"

function makeReq(overrides?: Record<string, unknown>) {
  return {
    method: "GET",
    path: "/api/health",
    headers: {},
    body: undefined,
    ...overrides,
  } as any
}

function makeRes() {
  let jsonBody: unknown = undefined
  let sendBody: unknown = undefined
  return {
    json: vi.fn((body: unknown) => { jsonBody = body }),
    send: vi.fn((body: unknown) => { sendBody = body }),
    setHeader: vi.fn(),
    status: vi.fn().mockReturnThis(),
    end: vi.fn(),
    locals: {},
    _jsonBody: () => jsonBody,
    _sendBody: () => sendBody,
  } as any
}

describe("Express adapter", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("calls next without modifying response", () => {
    const middleware = createSeptr({ secrets: false, bola: false, rateLimit: false })
    const req = makeReq()
    const res = makeRes()
    const next = vi.fn()

    middleware(req, res, next)

    expect(next).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
  })

  it("rate limits requests", () => {
    const middleware = createSeptr({ rateLimit: true, rateLimitConfig: { max: 2, windowMs: 60000 } })
    const next = vi.fn()

    middleware(makeReq({ headers: { "x-forwarded-for": "1.2.3.4" } }), makeRes(), next)
    middleware(makeReq({ headers: { "x-forwarded-for": "1.2.3.4" } }), makeRes(), next)
    const res = makeRes()
    middleware(makeReq({ headers: { "x-forwarded-for": "1.2.3.4" } }), res, next)

    expect(res.status).toHaveBeenCalledWith(429)
    expect(next).toHaveBeenCalledTimes(2) // only first 2 passed through
  })

  it("GETs on auth routes use the general limiter, not the strict auth limiter", () => {
    const middleware = createSeptr({ rateLimit: true, rateLimitConfig: { max: 2, windowMs: 60000 }, bola: false, secrets: false })
    const next = vi.fn()

    middleware(makeReq({ method: "GET", path: "/auth/me", headers: { "x-forwarded-for": "1.2.3.4" } }), makeRes(), next)
    middleware(makeReq({ method: "GET", path: "/auth/me", headers: { "x-forwarded-for": "1.2.3.4" } }), makeRes(), next)
    const res = makeRes()
    middleware(makeReq({ method: "GET", path: "/auth/me", headers: { "x-forwarded-for": "1.2.3.4" } }), res, next)

    // General max 2 applies to GET session probes — if the strict 10/min
    // auth limiter were used instead, this 3rd request would not be blocked.
    expect(res.status).toHaveBeenCalledWith(429)
  })

  it("POSTs on auth routes keep the strict auth limiter", () => {
    const middleware = createSeptr({ rateLimit: true, rateLimitConfig: { max: 100, windowMs: 60000 }, bola: false, secrets: false })
    const next = vi.fn()

    for (let i = 0; i < 10; i++) {
      middleware(makeReq({ method: "POST", path: "/auth/login", headers: { "x-forwarded-for": "1.2.3.4" } }), makeRes(), next)
    }
    const res = makeRes()
    middleware(makeReq({ method: "POST", path: "/auth/login", headers: { "x-forwarded-for": "1.2.3.4" } }), res, next)

    // Credential-submitting POSTs keep the strict 10/min limiter.
    expect(res.status).toHaveBeenCalledWith(429)
  })

  it("strips secrets from JSON responses", () => {
    const middleware = createSeptr({ secrets: true, bola: false, rateLimit: false })
    const req = makeReq()
    const res = makeRes()
    const next = vi.fn()

    middleware(req, res, next)
    res.json({ apiKey: "sk-proj-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" })

    expect(res.setHeader).toHaveBeenCalledWith("X-Septr-Stripped", "1")
  })

  it("blocks BOLA in strict mode", () => {
    const middleware = createSeptr({
      bola: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
    })
    const token = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiJ1c2VyXzEyMyJ9.signature"
    const req = makeReq({ path: "/api/users/:userId", headers: { authorization: `Bearer ${token}` } })
    const res = makeRes()
    const next = vi.fn()

    middleware(req, res, next)

    expect(res.status).toHaveBeenCalledWith(404)
    expect(res.end).toHaveBeenCalled()
  })

  it("sanitizes input in POST", () => {
    const middleware = createSeptr({
      inputSanitize: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
      bola: false,
    })
    const req = makeReq({ method: "POST", body: { name: "1 UNION SELECT * FROM users" } })
    const res = makeRes()
    const next = vi.fn()

    middleware(req, res, next)

    expect(res.status).toHaveBeenCalledWith(400)
  })

  it("skips middleware when locals.vibeShieldSkip is set", () => {
    const middleware = createSeptr({ rateLimit: true, rateLimitConfig: { max: 0, windowMs: 60000 } })
    const req = makeReq()
    const res = makeRes()
    res.locals = { vibeShieldSkip: true }
    const next = vi.fn()

    middleware(req, res, next)

    expect(next).toHaveBeenCalled()
  })

  it("sets X-Septr-Stripped header when stripping", () => {
    const middleware = createSeptr({ secrets: true, bola: false, rateLimit: false })
    const req = makeReq()
    const res = makeRes()
    const next = vi.fn()

    middleware(req, res, next)
    res.json({ password: "secret" })

    expect(res.setHeader).toHaveBeenCalledWith("X-Septr-Stripped", "1")
  })

  it("strips secrets from send() with object body", () => {
    const middleware = createSeptr({ secrets: true, bola: false, rateLimit: false })
    const req = makeReq()
    const res = makeRes()
    const next = vi.fn()

    middleware(req, res, next)
    res.send({ apiKey: "sk-proj-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" })

    expect(res.setHeader).toHaveBeenCalledWith("X-Septr-Stripped", "1")
  })
})
