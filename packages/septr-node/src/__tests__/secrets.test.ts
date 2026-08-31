import { describe, it, expect } from "vitest"
import { detectSecrets, detectHighEntropySecrets, shouldStripKey } from "../core/secrets"

describe("detectSecrets", () => {
  it("detects OpenAI API keys", () => {
    const result = detectSecrets("sk-proj-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    expect(result.length).toBeGreaterThan(0)
    expect(result[0].type).toBe("secret_exposure")
    expect(result[0].patternId).toContain("openai")
  })

  it("detects AWS keys", () => {
    const result = detectSecrets("AKIA" + "XXXXXXXXXXXXXXXX")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects AWS secret keys", () => {
    const result = detectSecrets("wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects Stripe live keys", () => {
    const result = detectSecrets("sk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects JWT tokens", () => {
    const result = detectSecrets("eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects private keys", () => {
    const result = detectSecrets("-----BEGIN PRIVATE" + " KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE" + " KEY-----")
    expect(result.length).toBeGreaterThan(0)
  })

  it("detects database URIs", () => {
    const result = detectSecrets("postgres://user:" + "password@localhost:5432/db")
    expect(result.length).toBeGreaterThan(0)
  })

  it("returns empty for safe input", () => {
    const result = detectSecrets("hello world this is safe")
    expect(result.length).toBe(0)
  })

  it("matches custom patterns", () => {
    const result = detectSecrets("my-secret-token-12345", ["secret-token-\\d+"])
    expect(result.length).toBeGreaterThan(0)
    expect(result[0].patternId).toBe("secret_custom")
  })

  it("handles empty string", () => {
    expect(detectSecrets("")).toEqual([])
  })

  it("configures severity correctly", () => {
    const privateKey = detectSecrets("-----BEGIN EC PRIVATE" + " KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END EC PRIVATE" + " KEY-----")
    expect(privateKey[0].severity).toBe("critical")

    const stripe = detectSecrets("sk_live_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    expect(stripe[0].severity).toBe("high")

    const github = detectSecrets("ghp_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    expect(github[0].severity).toBe("high")
  })
})

describe("shouldStripKey", () => {
  it("strips known sensitive keys", () => {
    expect(shouldStripKey("password")).toBe(true)
    expect(shouldStripKey("apiKey")).toBe(true)
    expect(shouldStripKey("credit_card")).toBe(true)
    expect(shouldStripKey("ssn")).toBe(true)
  })

  it("strips normalized variants", () => {
    expect(shouldStripKey("API_KEY")).toBe(true)
    expect(shouldStripKey("CreditCard")).toBe(true)
  })

  it("does not strip safe keys", () => {
    expect(shouldStripKey("name")).toBe(false)
    expect(shouldStripKey("email")).toBe(false)
    expect(shouldStripKey("description")).toBe(false)
  })

  it("strips custom fields", () => {
    expect(shouldStripKey("myCustomField", ["myCustomField"])).toBe(true)
  })

  it("handles empty key", () => {
    expect(shouldStripKey("")).toBe(false)
  })
})

describe("enhanced secret patterns", () => {
  it("detects OpenAI service account keys", () => {
    const events = detectSecrets("sk-svcacct-" + "abcdefghijklmnopqrstuvwxyz123456")
    expect(events.some((e) => e.patternId === "secret_openai_svc")).toBe(true)
  })

  it("detects GitHub fine-grained tokens", () => {
    const events = detectSecrets("github_pat_" + "11ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
    expect(events.some((e) => e.patternId === "secret_github_fine_grained")).toBe(true)
  })

  it("detects Twilio keys", () => {
    const events = detectSecrets("SK0123456789abcdef" + "0123456789abcdef")
    expect(events.some((e) => e.patternId === "secret_twilio")).toBe(true)
  })

  it("detects Slack webhooks", () => {
    const events = detectSecrets("https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")
    expect(events.some((e) => e.patternId === "secret_slack_webhook")).toBe(true)
  })

  it("detects Shopify tokens", () => {
    const events = detectSecrets("shpat_" + "0123456789abcdef0123456789abcdef")
    expect(events.some((e) => e.patternId === "secret_shopify")).toBe(true)
  })

  it("detects Discord bot tokens", () => {
    const events = detectSecrets("M0gQ1w2E3r4T5y6U7i8O9p0a.abcdef." + "ABCDEFGHIJKLMNOPQRSTUVWXYZA")
    expect(events.some((e) => e.patternId === "secret_discord_bot")).toBe(true)
  })

  it("detects Supabase service_role keys only with the right role", () => {
    const b64 = (d: unknown) => btoa(JSON.stringify(d)).replace(/=+$/, "")
    const header = b64({ alg: "HS256" })

    const svc = `${header}.${b64({ role: "service_role" })}.signature`
    const anon = `${header}.${b64({ role: "anon" })}.signature`

    const svcEvents = detectSecrets(svc)
    expect(svcEvents.some((e) => e.patternId === "secret_supabase_service_role")).toBe(true)
    expect(svcEvents.find((e) => e.patternId === "secret_supabase_service_role")!.severity).toBe("critical")

    const anonEvents = detectSecrets(anon)
    expect(anonEvents.some((e) => e.patternId === "secret_supabase_service_role")).toBe(false)
  })
})

describe("detectHighEntropySecrets", () => {
  it("detects high-entropy values assigned to secret-like keys", () => {
    const events = detectHighEntropySecrets('{"apiKey": "x9F2kQ7vL3pZ8nB4cD6mW1rT"}')
    expect(events.some((e) => e.patternId === "secret_high_entropy")).toBe(true)
  })

  it("skips UUID-like hex values", () => {
    const events = detectHighEntropySecrets('{"token": "3f2a9c1e-8b4d-47e6-9a2f-1c3d5e7b8a9f"}')
    expect(events).toEqual([])
  })

  it("skips values already matched by specific patterns", () => {
    const events = detectHighEntropySecrets('{"apiKey": "sk-proj-' + 'abcdefghijklmnopqrstuvwxyz1234567890"}')
    expect(events.some((e) => e.patternId === "secret_high_entropy")).toBe(false)
  })

  it("skips low-entropy and short values", () => {
    expect(detectHighEntropySecrets('{"token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')).toEqual([])
    expect(detectHighEntropySecrets('{"token": "short123"}')).toEqual([])
  })
})

describe("FP suppression", () => {
  it("Google API keys are advisory-only (no redaction)", () => {
    const events = detectSecrets("AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI")
    expect(events.length).toBeGreaterThan(0)
    expect(events[0].patternId).toBe("secret_google_api")
    expect(events[0].severity).toBe("low")
    expect(events[0].redactable).toBe(false)
  })

  it("Supabase anon keys are advisory-only", () => {
    const b64 = (d: unknown) => btoa(JSON.stringify(d)).replace(/=+$/, "")
    const anon = `${b64({ alg: "HS256" })}.${b64({ role: "anon" })}.signature`
    const events = detectSecrets(anon)
    expect(events.some((e) => e.patternId === "secret_supabase_anon")).toBe(true)
    expect(events.find((e) => e.patternId === "secret_supabase_anon")!.redactable).toBe(false)
  })

  it("Supabase anon JWT is not flagged as generic_jwt", () => {
    const b64 = (d: unknown) => btoa(JSON.stringify(d)).replace(/=+$/, "")
    const anon = `${b64({ alg: "HS256" })}.${b64({ role: "anon" })}.signature`
    const events = detectSecrets(anon)
    expect(events.some((e) => e.patternId === "secret_generic_jwt")).toBe(false)
  })

  it("Publishable keys are not flagged by high-entropy detector", () => {
    expect(detectHighEntropySecrets('{"apiKey": "pk_live_Y2xlcmsuY2xlcmsuY29tJA"}')).toEqual([])
    expect(detectHighEntropySecrets('{"apiKey": "phc_eNuN6Ojnk9O7uWfC17z12AK85fNR0BY6IiGVy0Gfwzw"}')).toEqual([])
  })
})
