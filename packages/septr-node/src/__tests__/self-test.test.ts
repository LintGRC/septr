import { describe, it, expect, vi } from "vitest"
import { runEngineSelfTest, scheduleStartupSelfTest } from "../core/self-test"

describe("runEngineSelfTest", () => {
  it("reports results for all 8 engines", () => {
    const results = runEngineSelfTest()
    expect(results).toHaveLength(8)
    const engines = results.map((r) => r.engine).sort()
    expect(engines).toEqual(
      ["bola", "missing_auth", "prompt_injection", "secrets", "sqli", "ssrf", "tamper", "xss"].sort(),
    )
  })

  it("all engines pass against known payloads", () => {
    const results = runEngineSelfTest()
    for (const r of results) {
      expect(r.passed, `engine ${r.engine} should detect its test payload`).toBe(true)
    }
  })
})

describe("scheduleStartupSelfTest", () => {
  it("is a no-op when telemetry is disabled", () => {
    expect(() =>
      scheduleStartupSelfTest({ apiKey: "vs_live_x", telemetry: false }),
    ).not.toThrow()
  })

  it("is a no-op without an api key", () => {
    expect(() => scheduleStartupSelfTest({})).not.toThrow()
  })

  it("is a no-op when selfTest is disabled", () => {
    expect(() =>
      scheduleStartupSelfTest({ apiKey: "vs_live_x", selfTest: false }),
    ).not.toThrow()
  })

  it("schedules a run when enabled (timers unref'd so the process can exit)", () => {
    const timers = vi.spyOn(globalThis, "setTimeout")
    scheduleStartupSelfTest({ apiKey: "vs_live_x", telemetry: true })
    expect(timers).toHaveBeenCalled()
    timers.mockRestore()
  })
})
