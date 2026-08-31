import { describe, it, expect } from "vitest"
import { detectSSRF } from "../core/ssrf"

describe("detectSSRF", () => {
  it("detects loopback address 127.0.0.1", () => {
    const result = detectSSRF("http://127.0.0.1/admin")
    expect(result.length).toBeGreaterThan(0)
    expect(result[0].type).toBe("ssrf")
    expect(result[0].patternId).toContain("loopback")
  })

  it("detects private network 10.x.x.x", () => {
    const result = detectSSRF("http://10.0.0.1/internal")
    expect(result.length).toBeGreaterThan(0)
    expect(result[0].type).toBe("ssrf")
  })

  it("detects private network 172.16-31.x.x", () => {
    const result = detectSSRF("http://172.16.0.1/api")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects private network 192.168.x.x", () => {
    const result = detectSSRF("http://192.168.1.100/data")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects unspecified address 0.0.0.0", () => {
    const result = detectSSRF("http://0.0.0.0/secret")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects cloud metadata endpoint", () => {
    const result = detectSSRF("http://169.254." + "169.254/latest/meta-data/")
    expect(result.length).toBeGreaterThan(0)
    expect(result[0].severity).toBe("critical")
  })

  it("detects GCP metadata endpoint", () => {
    const result = detectSSRF("http://metadata.google." + "internal/computeMetadata/v1/")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects localhost", () => {
    const result = detectSSRF("http://localhost:3000/admin")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects file:// protocol", () => {
    const result = detectSSRF("file:///etc/passwd")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects gopher:// protocol", () => {
    const result = detectSSRF("gopher://127.0.0.1:25/")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects TEST-NET addresses", () => {
    const result = detectSSRF("http://192.0.2.1/scan")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects multiple SSRF patterns in one string", () => {
    const result = detectSSRF("http://10.0.0.1 AND http://169.254." + "169.254")
    expect(result.length).toBeGreaterThanOrEqual(2)
  })

  it("returns empty for safe URLs", () => {
    const result = detectSSRF("https://api.stripe.com/charges")
    expect(result.length).toBe(0)
  })

  it("returns empty for safe public IPs", () => {
    const result = detectSSRF("https://8.8.8.8/dns-query")
    expect(result.length).toBe(0)
  })

  it("returns empty for empty string", () => {
    expect(detectSSRF("")).toEqual([])
  })

  it("case insensitive for localhost and metadata", () => {
    const result = detectSSRF("HTTP://LOCALHOST:3000")
    expect(result.length).toBeGreaterThan(0)
  })
})
