import test from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { spawn } from "node:child_process"

function startServer(routes) {
  return new Promise((done) => {
    const server = createServer((req, res) => {
      const route = routes[req.url || "/"]
      if (!route) { res.writeHead(404).end(); return }
      res.writeHead(route.status ?? 200, { "Content-Type": route.type ?? "text/html" })
      res.end(route.body)
    })
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address()
      done({ server, port: typeof addr === "object" && addr ? addr.port : 0 })
    })
  })
}

function runCli(args) {
  return new Promise((done) => {
    const child = spawn("node", ["bin/septr.js", ...args])
    let out = "", err = ""
    child.stdout.on("data", (d) => (out += d))
    child.stderr.on("data", (d) => (err += d))
    child.on("close", (code) => done({ code, out, err }))
  })
}

// Fixture secrets, assembled at runtime so the served bytes contain a
// contiguous secret (the engine must detect it) while the source file
// contains no secret-shaped literal (push protection / dogfood clean).
const STRIPE_FIXTURE = "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
const OPENAI_FIXTURE = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"

test("engine finds a hardcoded secret on the landing page", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html><script>const key = "' + STRIPE_FIXTURE + '";</script></html>' },
  })
  try {
    const { code, out } = await runCli(["scan", "--json", `http://127.0.0.1:${port}`])
    assert.equal(code, 1)
    const d = JSON.parse(out)
    const secret = d.findings.find((f) => f.patternId === "secret_stripe_live")
    assert.ok(secret, "stripe live secret detected in landing page body")
    assert.equal(secret.file, "/")
    assert.ok(!out.includes(STRIPE_FIXTURE), "raw secret leaked")
  } finally {
    server.close()
  }
})

test("engine finds a secret in a discovered endpoint body", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html><a href="/api/config">cfg</a></html>' },
    "/api/config": { body: '{"apiKey": "' + OPENAI_FIXTURE + '"}', type: "application/json" },
  })
  try {
    const { code, out } = await runCli(["scan", "--json", `http://127.0.0.1:${port}`])
    assert.equal(code, 1)
    const d = JSON.parse(out)
    const secret = d.findings.find((f) => f.patternId && f.patternId.includes("openai"))
    assert.ok(secret, "openai key detected in discovered endpoint")
    assert.equal(secret.file, "/api/config")
  } finally {
    server.close()
  }
})

test("engine finding appears in the attach payload alongside path findings", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html>const k="' + STRIPE_FIXTURE + '";</html>' },
    "/.env": { body: "DATABASE_URL=postgres://u:" + "p@db/app\nSECRET=abc123def456\n" },
  })
  try {
    const { code, out } = await runCli(["scan", "--report", `http://127.0.0.1:${port}`])
    assert.equal(code, 0)
    const payload = JSON.parse(out)
    const ids = payload.findings.map((f) => f.check_id)
    assert.ok(ids.includes("exposed_env"), "path finding present")
    assert.ok(ids.includes("stripe_live_secret"), "engine finding present")
  } finally {
    server.close()
  }
})

test("report-file renders both finding types", async () => {
  const { mkdtempSync, readFileSync } = await import("node:fs")
  const { tmpdir } = await import("node:os")
  const { join } = await import("node:path")
  const { server, port } = await startServer({
    "/": { body: '<html>const k="' + STRIPE_FIXTURE + '";</html>' },
  })
  try {
    const dir = mkdtempSync(join(tmpdir(), "septr-engine-"))
    const outPath = join(dir, "report.md")
    const { code } = await runCli(["scan", "--report-file", outPath, `http://127.0.0.1:${port}`])
    assert.equal(code, 1)
    const md = readFileSync(outPath, "utf-8")
    assert.ok(md.includes("secret_stripe_live"), "engine finding in report")
    assert.ok(md.includes("Engine: secrets"), "engine label in report")
    assert.ok(!md.includes(STRIPE_FIXTURE), "no raw secret in report")
  } finally {
    server.close()
  }
})
