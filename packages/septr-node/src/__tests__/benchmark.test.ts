import { describe, it, expect } from "vitest"
import { detectSSRF } from "../core/ssrf"
import { detectSQLi, detectXSS } from "../core/sanitize"
import { detectPromptInjection } from "../core/prompt-injection"
import { detectSecrets } from "../core/secrets"
import { ssrfPayloads } from "./benchmark/ssrf-payloads"
import { sqliPayloads } from "./benchmark/sqli-payloads"
import { xssPayloads } from "./benchmark/xss-payloads"
import { promptInjectionPayloads } from "./benchmark/prompt-injection-payloads"
import { secretsPayloads } from "./benchmark/secrets-payloads"

export interface BenchmarkPayload {
  input: string
  expect: boolean
  source: string
}

function runBench(
  name: string,
  payloads: BenchmarkPayload[],
  detect: (input: string) => unknown[],
) {
  describe(`Benchmark: ${name}`, () => {
    for (const p of payloads) {
      it(`${p.expect ? "detects" : "passes"} — ${p.source}`, () => {
        const result = detect(p.input)
        if (p.expect) {
          expect(result.length, `Expected "${p.input}" to be detected by ${name}`).toBeGreaterThan(0)
        } else {
          expect(result.length, `Expected "${p.input}" to be passed by ${name}`).toBe(0)
        }
      })
    }
  })
}

runBench("SSRF", ssrfPayloads, detectSSRF)
runBench("SQLi", sqliPayloads, (i) => detectSQLi(i))
runBench("XSS", xssPayloads, (i) => detectXSS(i))
runBench("Prompt Injection", promptInjectionPayloads, detectPromptInjection)
runBench("Secrets", secretsPayloads, (i) => detectSecrets(i))

describe("Benchmark: summary", () => {
  it("runs all benchmark payload files", () => {
    const total =
      ssrfPayloads.length +
      sqliPayloads.length +
      xssPayloads.length +
      promptInjectionPayloads.length +
      secretsPayloads.length
    expect(total).toBeGreaterThan(180)
    expect(total).toBeLessThan(210)
  })
})
