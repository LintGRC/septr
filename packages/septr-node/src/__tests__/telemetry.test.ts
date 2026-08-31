import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import type { DetectionEvent } from "../core/types"
import { TelemetryManager, initTelemetry, destroyTelemetry, emitEvent, flushSync } from "../core/telemetry"

function makeEvent(overrides?: Partial<DetectionEvent>): DetectionEvent {
  return {
    type: "bola",
    severity: "high",
    patternId: "test_pattern",
    description: "Test detection",
    timestamp: Date.now(),
    ...overrides,
  }
}

describe("TelemetryManager", () => {
  let manager: TelemetryManager

  beforeEach(() => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response(null, { status: 200 })),
    ) as unknown as typeof fetch
    manager = new TelemetryManager({ telemetry: true }, "test-project")
  })

  afterEach(() => {
    manager.destroy()
    vi.restoreAllMocks()
  })

  it("buffers events", () => {
    manager.emit(makeEvent())
    expect(manager.queueSize).toBe(1)
  })

  it("does not buffer when telemetry is false", () => {
    const disabled = new TelemetryManager({ telemetry: false }, "test-project")
    disabled.emit(makeEvent())
    expect(disabled.queueSize).toBe(0)
    disabled.destroy()
  })

  it("does not emit after destroy", () => {
    manager.destroy()
    manager.emit(makeEvent())
    expect(manager.queueSize).toBe(0)
  })

  it("flushes when batch size is reached", () => {
    for (let i = 0; i < 50; i++) {
      manager.emit(makeEvent())
    }
    expect(manager.queueSize).toBeLessThan(50)
    expect(fetch).toHaveBeenCalled()
  })

  it("drops oldest events when buffer overflows", () => {
    for (let i = 0; i < 550; i++) {
      manager.emit(makeEvent())
    }
    expect(manager.queueSize).toBeLessThanOrEqual(500)
  })

  it("sends events via fetch", async () => {
    manager.emit(makeEvent())
    await manager.flush()
    expect(fetch).toHaveBeenCalledWith(
      "https://api.septr.com/v1/events",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
        }),
      }),
    )
  })

  it("retries on failure with backoff", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error("Network error"))
    const m = new TelemetryManager({ telemetry: true }, "test-project")
    m.emit(makeEvent())
    await m.flush()
    expect(m["currentFlushInterval"]).toBeGreaterThan(30000)
    m.destroy()
  })
})

describe("module-level singleton", () => {
  beforeEach(() => {
    destroyTelemetry()
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response(null, { status: 200 })),
    ) as unknown as typeof fetch
  })

  afterEach(() => {
    destroyTelemetry()
    vi.restoreAllMocks()
  })

  it("initTelemetry creates a manager", () => {
    initTelemetry({ telemetry: true }, "test-project")
    expect(() => emitEvent(makeEvent(), { telemetry: true })).not.toThrow()
  })

  it("emitEvent does not throw when no manager initialized", () => {
    expect(() => emitEvent(makeEvent(), { telemetry: true })).not.toThrow()
  })

  it("emitEvent respects telemetry=false config", () => {
    initTelemetry({ telemetry: true }, "test-project")
    expect(() => emitEvent(makeEvent(), { telemetry: false })).not.toThrow()
  })

  it("flushSync returns a promise", async () => {
    await expect(flushSync()).resolves.toBeUndefined()
  })

  it("destroyTelemetry cleans up", () => {
    initTelemetry({ telemetry: true }, "test-project")
    destroyTelemetry()
    emitEvent(makeEvent(), { telemetry: true })
    expect(flushSync()).resolves.toBeUndefined()
  })

  it("sendTestResults emits per-engine events and flushes immediately", async () => {
    const m = new TelemetryManager({ telemetry: true }, "test-project")
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>
    m.sendTestResults([
      { engine: "secrets", passed: true },
      { engine: "sqli", passed: false },
    ])
    // 2 test result events + 1 __verified__ event are sent right away
    await vi.waitFor(() => {
      const call = fetchMock.mock.calls.at(-1)
      expect(call).toBeTruthy()
      const body = JSON.parse((call![1] as RequestInit).body as string)
      const routes = (body.events as Array<{ route?: string; description: string }>).map((e) => e.route)
      expect(routes.filter((r) => r === "__test_result__")).toHaveLength(2)
      expect(routes.filter((r) => r === "__verified__")).toHaveLength(1)
    })
    m.destroy()
  })
})
