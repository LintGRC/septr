import { describe, it, expect } from "vitest"
import { canonicalFinding, canonicalCheckId } from "../core/check-ids"

describe("canonicalFinding", () => {
  it("maps CLI secret patternIds to canonical check ids with web names/severities", () => {
    const stripe = canonicalFinding("secret_stripe_live")
    expect(stripe.checkId).toBe("stripe_live_secret")
    expect(stripe.name).toBe("Stripe live secret key exposed")
    expect(stripe.severity).toBe("critical")

    const openai = canonicalFinding("secret_openai_svc")
    expect(openai.checkId).toBe("openai_key")
    expect(openai.name).toBe("OpenAI API key exposed")
    expect(openai.severity).toBe("critical")
  })

  it("classifies probe findings as exposed_file / exposed_env", () => {
    expect(canonicalCheckId("probe__git_config", "/.git/config")).toBe("exposed_file")
    expect(canonicalCheckId("probe__env", "/.env")).toBe("exposed_env")
    expect(canonicalCheckId("probe__env_local", "/.env.local")).toBe("exposed_env")
  })

  it("passes through header findings unchanged (labels are canonical already)", () => {
    const header = canonicalFinding("missing_header", "/")
    expect(header.checkId).toBe("missing_header")
    expect(header.name).toBeUndefined()
    expect(header.severity).toBeUndefined()
  })

  it("falls back to the bare id for unmapped patterns", () => {
    const slack = canonicalFinding("secret_slack_bot")
    expect(slack.checkId).toBe("slack_bot")
    expect(slack.name).toBeUndefined()
    expect(slack.severity).toBeUndefined()
  })
})
