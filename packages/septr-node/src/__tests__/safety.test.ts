import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"

vi.mock("../core/bola", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../core/bola")>()
  return {
    ...actual,
    extractTokenClaims: () => {
      throw new Error("engine exploded")
    },
  }
})

import { createSeptr } from "../adapters/express"
import { EngineGuard, killSwitchEngaged } from "../core/safety"

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

describe("EngineGuard", () => {
  it("returns the fallback on throw", () => {
    const g = new EngineGuard()
    expect(g.run("e", () => { throw new Error("boom") }, "def")).toBe("def")
    expect(g.isOpen("e")).toBe(false)
  })

  it("opens after threshold, skips after, reports once", () => {
    const reported: string[] = []
    const g = new EngineGuard({ failureThreshold: 2, onDegraded: (e) => reported.push(e) })
    const boom = () => { throw new Error("boom") }
    expect(g.run("e", boom, 0)).toBe(0)
    expect(g.run("e", boom, 0)).toBe(0)
    expect(g.isOpen("e")).toBe(true)
    let ran = false
    expect(g.run("e", () => { ran = true; return 1 }, 0)).toBe(0)
    expect(ran).toBe(false)
    expect(reported).toEqual(["e"])
  })

  it("isolates engines", () => {
    const g = new EngineGuard({ failureThreshold: 1 })
    g.run("a", () => { throw new Error("boom") }, 0)
    expect(g.isOpen("a")).toBe(true)
    expect(g.isOpen("b")).toBe(false)
    expect(g.run("b", () => 7, 0)).toBe(7)
  })

  it("marks calls over the time budget as failures", () => {
    const g = new EngineGuard({ failureThreshold: 1, budgetMs: 1 })
    const slow = () => {
      const start = Date.now()
      while (Date.now() - start < 15) { /* busy wait */ }
      return "ok"
    }
    expect(g.run("e", slow, "def")).toBe("ok")
    expect(g.isOpen("e")).toBe(true)
  })
})

describe("kill switch", () => {
  afterEach(() => {
    delete process.env.SEPTR_DISABLED
  })

  it("reads the env var", () => {
    process.env.SEPTR_DISABLED = "true"
    expect(killSwitchEngaged()).toBe(true)
    process.env.SEPTR_DISABLED = "0"
    expect(killSwitchEngaged()).toBe(false)
  })

  it("bypasses the middleware entirely", () => {
    process.env.SEPTR_DISABLED = "true"
    const middleware = createSeptr({ secrets: true, bola: true, rateLimit: true, telemetry: false })
    const req = makeReq()
    const res = makeRes()
    const originalJson = res.json
    const next = vi.fn()

    middleware(req, res, next)

    expect(next).toHaveBeenCalled()
    expect(res.json).toBe(originalJson)
  })
})

describe("fail-open", () => {
  beforeEach(() => {
    delete process.env.SEPTR_DISABLED
  })

  it("passes the request through when the pipeline throws", () => {
    const middleware = createSeptr({
      bola: true,
      secrets: false,
      rateLimit: false,
      inputSanitize: false,
      telemetry: false,
    })
    const req = makeReq({ headers: { authorization: "Bearer abc.def.ghi" }, path: "/api/data" })
    const res = makeRes()
    const next = vi.fn()

    middleware(req, res, next)

    expect(next).toHaveBeenCalled()
  })
})
