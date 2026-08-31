import test from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { spawn } from "node:child_process"
import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

function startServer(routes, headers = {}) {
  return new Promise((done) => {
    const server = createServer((req, res) => {
      const route = routes[req.url || "/"]
      if (!route) { res.writeHead(404).end(); return }
      res.writeHead(route.status ?? 200, { "Content-Type": route.type ?? "text/html", ...headers })
      res.end(route.body)
    })
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address()
      done({ server, port: typeof addr === "object" && addr ? addr.port : 0 })
    })
  })
}

test("crawl discovers same-origin endpoints from the root page", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html><a href="/api/health">health</a><a href="/dashboard">dash</a><a href="https://evil.com/x">x</a><link rel="stylesheet" href="/styles.css"></html>' },
    "/api/health": { body: "ok", type: "application/json" },
    "/dashboard": { body: "<html>dash</html>" },
    "/styles.css": { body: "body{}", type: "text/css" },
  })
  try {
    const { probeUrl } = await import("../dist/core/probe.js")
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    const paths = r.endpoints.map((e) => e.path)
    assert.ok(paths.includes("/api/health"), "discovered /api/health")
    assert.ok(paths.includes("/dashboard"), "discovered /dashboard")
    assert.ok(!paths.includes("/styles.css"), "static assets skipped")
    assert.ok(!paths.includes("/x"), "cross-origin skipped")
    assert.equal(r.endpoints.find((e) => e.path === "/api/health").contentType, "application/json")
  } finally {
    server.close()
  }
})

test("fingerprint detects v0 + next markers and server header", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html data-v0-abc="1"><script src="/_next/static/x.js"></script></html>' },
  }, { "server": "Vercel", "x-vercel-id": "cle1::abc" })
  try {
    const { probeUrl } = await import("../dist/core/probe.js")
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 2 })
    assert.ok(r.fingerprint.frameworks.includes("v0"), "v0 marker")
    assert.ok(r.fingerprint.frameworks.includes("next"), "next marker")
    assert.ok(r.fingerprint.frameworks.includes("vercel"), "vercel header")
    assert.equal(r.fingerprint.server, "Vercel")
  } finally {
    server.close()
  }
})

test("--report-file writes a markdown report with reproduction steps", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html><a href="/api/x">x</a></html>' },
    "/.env": { body: "DATABASE_URL=postgres://u:" + "p@db/app\nSECRET=abc123def456\n" },
    "/api/x": { body: "{}", type: "application/json" },
  })
  try {
    const dir = mkdtempSync(join(tmpdir(), "septr-report-"))
    const outPath = join(dir, "report.md")
    const { code } = await new Promise((done) => {
      const child = spawn("node", ["bin/septr.js", "scan", "--report-file", outPath, `http://127.0.0.1:${port}`])
      let err = ""
      child.stderr.on("data", (d) => (err += d))
      child.on("close", (c) => done({ code: c, err }))
    })
    assert.equal(code, 1) // critical finding present
    const md = readFileSync(outPath, "utf-8")
    assert.ok(md.includes("# Septr scan report"))
    assert.ok(md.includes("### CRITICAL — /.env"))
    assert.ok(md.includes("Reproduction: `curl http://127.0.0.1:") + "port")
    assert.ok(md.includes("/.env`"))
    assert.ok(md.includes("## Discovered endpoints"))
    assert.ok(md.includes("/api/x"))
    assert.ok(md.includes("Authorized assessment only"))
    assert.ok(!md.includes("abc123def456"), "report must not leak raw secrets")
  } finally {
    server.close()
  }
})
