import { describe, it, expect, vi, beforeEach } from "vitest"

const calls = vi.hoisted(() => ({ count: 0 }))

vi.mock("../core/headers", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../core/headers")>()
  return {
    ...actual,
    detectMissingSecurityHeaders: () => {
      calls.count++
      return []
    },
  }
})

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
  return {
    json: vi.fn(),
    send: vi.fn(),
    setHeader: vi.fn(),
    status: vi.fn().mockReturnThis(),
    end: vi.fn(),
    localHeaders: {} as Record<string, string>,
    getHeaders: function () {
      return this.localHeaders
    },
    locals: {},
  } as any
}

describe("securityHeaders option", () => {
  beforeEach(() => {
    calls.count = 0
  })

  it("runs the header advisory by default", () => {
    const middleware = createSeptr({ secrets: false, bola: false, rateLimit: false, telemetry: false })
    const res = makeRes()
    middleware(makeReq(), res, vi.fn())
    res.json({ ok: true })
    expect(calls.count).toBeGreaterThan(0)
  })

  it("skips the header advisory when disabled", () => {
    const middleware = createSeptr({
      secrets: false,
      bola: false,
      rateLimit: false,
      telemetry: false,
      securityHeaders: false,
    })
    const res = makeRes()
    middleware(makeReq(), res, vi.fn())
    res.json({ ok: true })
    expect(calls.count).toBe(0)
  })
})
