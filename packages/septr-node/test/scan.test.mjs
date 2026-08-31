import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { scanDir } from "../dist/core/scan.js"

// The vulnerable fixture tree is generated at test time in a temp dir so no
// secret-shaped literal ever appears in the repo source (push protection +
// dogfood: `septr scan .` on this repo must report zero findings). The
// literals are assembled at runtime; the scanner sees the contiguous values.
const STRIPE_FIXTURE = "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
const SUPABASE_FIXTURE = "eyJhbGciOiJIUzI1NiJ9." + "eyJyb2xlIjoic2VydmljZV9yb2xlIn0.signature"
const SSRF_FIXTURE = "http://169.254." + "169.254/latest/meta-data/"
const SQLI_BODY = " OR 1=" + "1 --"
const XSS_FIXTURE = "<img src=x " + "onerror=alert(1)>"
const RSA_FIXTURE =
  "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cAFj\npKzALoX0ySbYKi8OQ8YhY1yzdfQZz2E3QxMhGqQ1jVQ9cC2r5PZxVwZaP0Z0Jm7\n-----END RSA PRIVATE" + " KEY-----"

function buildVulnFixture(dir) {
  const src = join(dir, "src")
  const vendored = join(dir, "pkg", "mod", "golang.org", "x", "crypto")
  mkdirSync(src, { recursive: true })
  mkdirSync(vendored, { recursive: true })
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "vuln-fixture" }, null, 2))
  writeFileSync(
    join(src, "index.js"),
    [
      `const stripe = "${STRIPE_FIXTURE}"`,
      `const supabaseKey = "${SUPABASE_FIXTURE}"`,
      `const query = "SELECT * FROM users WHERE id = " + req.params.id + "${SQLI_BODY}"`,
      `const img = "${XSS_FIXTURE}"`,
      `const url = "${SSRF_FIXTURE}"`,
      `console.log(stripe)`,
      "",
    ].join("\n"),
  )
  writeFileSync(join(vendored, "keys.go"), `package crypto\nconst testKey = "${RSA_FIXTURE}"\n`)
}

function withVulnFixture(fn) {
  const dir = mkdtempSync(join(tmpdir(), "septr-vuln-"))
  try {
    buildVulnFixture(dir)
    return fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test("clean fixture: zero findings", () => {
  const r = scanDir(new URL("../fixtures/clean", import.meta.url).pathname)
  assert.equal(r.findings.length, 0)
  assert.equal(r.hygiene.gitignoreMissing, false)
})

test("vuln fixture: secrets + sanitize + ssrf + hygiene", () => {
  withVulnFixture((dir) => {
    const r = scanDir(dir)
    const ids = r.findings.map((f) => f.patternId)
    assert.ok(ids.includes("secret_stripe_live"), "stripe live key")
    assert.ok(ids.includes("secret_supabase_service_role"), "role-verified service role")
    assert.ok(ids.some((i) => i.startsWith("sqli_")), "sqli")
    assert.ok(ids.some((i) => i.startsWith("xss_")), "xss")
    assert.ok(ids.some((i) => i.startsWith("ssrf_")), "ssrf")
    assert.equal(r.hygiene.gitignoreMissing, true)
  })
})

test("pkg/mod vendored testdata is pruned (no private_key finding)", () => {
  withVulnFixture((dir) => {
    const r = scanDir(dir)
    assert.ok(!r.findings.some((f) => f.patternId === "private_key"), "no private_key from pkg/mod")
  })
})

test("every finding is redacted", () => {
  withVulnFixture((dir) => {
    const r = scanDir(dir)
    for (const f of r.findings) {
      assert.ok(!f.preview.includes(STRIPE_FIXTURE), "raw secret leaked into preview")
    }
  })
})