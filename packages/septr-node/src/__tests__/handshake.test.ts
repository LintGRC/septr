import { describe, it, expect, vi, afterEach } from "vitest"
import { sendHandshake } from "../core/telemetry"

afterEach(() => {
  vi.restoreAllMocks()
})

const KEY = "septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab"

describe("sendHandshake", () => {
  it("posts runtime/package/version and returns true on connected", async () => {
    const fetchMock = vi.fn(async () => {
      return {
        ok: true,
        status: 200,
        json: async () => ({ status: "connected", project: { id: "p1", name: "Demo" } }),
      }
    })
    vi.stubGlobal("fetch", fetchMock)

    const ok = await sendHandshake({ apiKey: KEY, telemetryUrl: "https://api.septr.com/v1/events", framework: "express" })

    expect(ok).toBe(true)
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    const headers = init.headers as Record<string, string>
    expect(url).toBe("https://api.septr.com/v1/handshake")
    expect(headers.Authorization).toBe(`Bearer ${KEY}`)
    expect(JSON.parse(init.body as string)).toMatchObject({
      runtime: "express",
      package: "septr",
      version: expect.any(String),
      environment: "test",
    })
  })

  it("strips /events from custom telemetry URLs", async () => {
    const fetchMock = vi.fn(async () => {
      return {
        ok: true,
        status: 200,
        json: async () => ({ status: "connected", project: {} }),
      }
    })
    vi.stubGlobal("fetch", fetchMock)

    await sendHandshake({ apiKey: KEY, telemetryUrl: "http://localhost:8000/v1/events" })
    const [url] = fetchMock.mock.calls[0] as unknown as [string]
    expect(url).toBe("http://localhost:8000/v1/handshake")
  })

  it("returns false without a key", async () => {
    const ok = await sendHandshake({})
    expect(ok).toBe(false)
  })

  it("returns false on non-200", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 401 })))
    const ok = await sendHandshake({ apiKey: KEY })
    expect(ok).toBe(false)
  })

  it("returns false on network failure", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("boom")
    }))
    const ok = await sendHandshake({ apiKey: KEY })
    expect(ok).toBe(false)
  })
})
