import { describe, it, expect, afterEach, vi } from "vitest"
import type { SeptrConfig } from "../core/types"
import {
  configPullEnabled,
  fetchProjectConfig,
  applyRemoteConfig,
  startConfigPolling,
  stopConfigPolling,
} from "../core/config-pull"

function fetchOk(body: unknown, status = 200): ReturnType<typeof vi.fn> {
  return vi.fn(() =>
    Promise.resolve(new Response(JSON.stringify(body), { status })),
  ) as unknown as ReturnType<typeof vi.fn>
}

const VALID_KEY = "septr_live_11111111-2222-3333-4444-555555555555_abcd0123456789abcdef0123456789ab"

afterEach(() => {
  stopConfigPolling()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe("configPullEnabled", () => {
  it("is enabled with an apiKey", () => {
    expect(configPullEnabled({ apiKey: "x" })).toBe(true)
  })

  it("is disabled when remoteConfig is false", () => {
    expect(configPullEnabled({ apiKey: "x", remoteConfig: false })).toBe(false)
  })

  it("is disabled without an apiKey", () => {
    expect(configPullEnabled({ telemetry: true })).toBe(false)
  })
})

describe("applyRemoteConfig", () => {
  it("merges only runtime keys", () => {
    const config: SeptrConfig = { apiKey: "k", strictMode: false, telemetryUrl: "http://x/events" }
    applyRemoteConfig(config, {
      strictMode: true,
      bola: false,
      apiKey: "evil",
      telemetryUrl: "http://evil",
    })
    expect(config.strictMode).toBe(true)
    expect(config.bola).toBe(false)
    expect(config.apiKey).toBe("k")
    expect(config.telemetryUrl).toBe("http://x/events")
  })

  it("no-ops on empty remote", () => {
    const config: SeptrConfig = { strictMode: false }
    expect(applyRemoteConfig(config, {})).toBe(false)
  })
})

describe("fetchProjectConfig", () => {
  it("parses v2 key into the config URL", async () => {
    const mockFetch = fetchOk({ config: { strictMode: true } })
    vi.stubGlobal("fetch", mockFetch)

    const result = await fetchProjectConfig({
      apiKey: VALID_KEY,
      telemetryUrl: "http://127.0.0.1:8000/events",
    })

    expect(result).toEqual({ strictMode: true })
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(
      "http://127.0.0.1:8000/projects/11111111-2222-3333-4444-555555555555/config",
    )
    expect(init.headers).toMatchObject({ Authorization: `Bearer ${VALID_KEY}` })
  })

  it("returns null on non-200", async () => {
    vi.stubGlobal("fetch", fetchOk({}, 401))
    const result = await fetchProjectConfig({ apiKey: VALID_KEY, telemetryUrl: "http://x/events" })
    expect(result).toBeNull()
  })

  it("returns null on network error", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("down"))))
    const result = await fetchProjectConfig({ apiKey: VALID_KEY, telemetryUrl: "http://x/events" })
    expect(result).toBeNull()
  })
})

describe("startConfigPolling", () => {
  it("applies remote config on startup", async () => {
    const mockFetch = fetchOk({ config: { strictMode: true } })
    vi.stubGlobal("fetch", mockFetch)

    const config: SeptrConfig = { apiKey: VALID_KEY, telemetryUrl: "http://x/events" }
    await startConfigPolling(config)

    expect(config.strictMode).toBe(true)
  })

  it("does nothing when disabled", async () => {
    const mockFetch = fetchOk({ config: { strictMode: true } })
    vi.stubGlobal("fetch", mockFetch)

    await startConfigPolling({ apiKey: "x", remoteConfig: false })
    expect(mockFetch).not.toHaveBeenCalled()
  })
})
