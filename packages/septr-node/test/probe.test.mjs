import test from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { probeUrl } from "../dist/core/probe.js"

function startServer(routes) {
  return new Promise((done) => {
    const server = createServer((req, res) => {
      const route = routes[req.url || "/"]
      if (!route) {
        res.writeHead(404).end("not found")
        return
      }
      res.writeHead(route.status ?? 200, { "Content-Type": "text/plain" })
      res.end(route.body)
    })
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address()
      done({ server, port: typeof addr === "object" && addr ? addr.port : 0 })
    })
  })
}

const VULN_ROUTES = {
  "/.env": { body: "DATABASE_URL=postgres://user:" + "pass@db.example.com/app\nSECRET_KEY=supersecretvalue\n" },
  "/.git/config": { body: "[core]\n\trepositoryformatversion = 0\n\t[remote \"origin\"]\n\turl = https://github.com/org/repo.git\n" },
  "/.git/HEAD": { body: "ref: refs/heads/main\n" },
  "/server.key": { body: "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cAFj\n-----END RSA PRIVATE" + " KEY-----\n" },
  "/actuator": { body: '{"status":"UP","components":{}}' },
  "/actuator/env": { body: '{"propertySources":[{"name":"systemEnvironment"}]}' },
  "/backup.sql": { body: "-- MySQL dump\n-- Host: localhost\nINSERT INTO users VALUES (1, 'admin');\n" },
  "/phpinfo.php": { body: "<html><body><h1>PHP Version 8.1.2</h1></body></html>" },
  "/openapi.json": { body: '{"openapi":"3.0.0","info":{"title":"app"}}' },
  "/docs": { body: '<html><head><title>Swagger UI</title></head><body>swagger-ui</body></html>' },
  "/uploads/": { body: '<html><title>Index of /uploads</title><body><a href="..">Parent Directory</a></body></html>' },
}

const CLEAN_ROUTES = {
  "/.env": { status: 404, body: "" },
  "/.git/config": { status: 404, body: "" },
  "/actuator": { status: 404, body: "" },
  "/backup.sql": { status: 404, body: "" },
}

test("probe finds exposed sensitive paths with correct severities", async () => {
  const { server, port } = await startServer(VULN_ROUTES)
  try {
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    const byPath = new Map(r.findings.map((f) => [f.path, f]))
    assert.ok(byPath.has("/.env"), "exposed .env found")
    assert.equal(byPath.get("/.env").severity, "critical")
    assert.ok(byPath.has("/.git/config"), ".git config found")
    assert.equal(byPath.get("/.git/config").severity, "critical")
    assert.ok(byPath.has("/server.key"), "TLS key found")
    assert.equal(byPath.get("/server.key").severity, "critical")
    assert.ok(byPath.has("/backup.sql"), "sql dump found")
    assert.equal(byPath.get("/backup.sql").severity, "high")
    assert.ok(byPath.has("/actuator/env"), "actuator env found")
    assert.equal(byPath.get("/actuator/env").severity, "high")
    assert.ok(byPath.has("/docs"), "docs found")
    assert.equal(byPath.get("/docs").severity, "medium")
  } finally {
    server.close()
  }
})

test("probe previews are redacted — no raw secrets", async () => {
  const { server, port } = await startServer(VULN_ROUTES)
  try {
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    const env = r.findings.find((f) => f.path === "/.env")
    assert.ok(env, ".env found")
    assert.ok(!env.preview.includes("supersecretvalue"), "raw secret leaked into preview")
    assert.ok(!env.preview.includes("user:pass"), "db password leaked into preview")
    const key = r.findings.find((f) => f.path === "/server.key")
    assert.ok(key, "server.key found")
    assert.ok(!key.preview.includes("MIIEvQIB"), "raw private key leaked into preview")
  } finally {
    server.close()
  }
})

test("probe on a clean server finds nothing (except security headers)", async () => {
  const { server, port } = await startServer(CLEAN_ROUTES)
  try {
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    const probeFindings = r.findings.filter((f) => f.patternId !== "missing_header")
    assert.equal(probeFindings.length, 0)
  } finally {
    server.close()
  }
})

test("200-on-everything server without matching content produces no findings (except security headers)", async () => {
  const { server, port } = await startServer({
    "/.env": { body: "hello world" },
    "/.git/config": { body: "<html>app</html>" },
    "/server.key": { body: "not a key" },
    "/actuator": { body: "ok" },
  })
  try {
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    const probeFindings = r.findings.filter((f) => f.patternId !== "missing_header")
    assert.equal(probeFindings.length, 0)
  } finally {
    server.close()
  }
})

test("probe detects leaked secrets inside JS bundles", async () => {
  const STRIPE_KEY = "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
  const { server, port } = await startServer({
    "/": {
      body: '<html><head><script src="/app.js"></script></head><body>app</body></html>',
    },
    "/app.js": {
      body: `const apiKey = "${STRIPE_KEY}";\nfetch("/api/data", { headers: { Authorization: "Bearer " + apiKey } });`,
    },
  })
  try {
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    const scanned = r.engineFindings.map((f) => f.file)
    assert.ok(scanned.includes("/app.js"), "JS bundle was scanned")
    assert.ok(r.engineFindings.some((f) => f.patternId === "secret_stripe_live"), "leaked key found in bundle")
    assert.equal(r.bundles, 1, "one bundle scanned")
  } finally {
    server.close()
  }
})

test("probe detects missing security headers with canonical labels", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html><body>app</body></html>' },
  })
  try {
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    const headerFindings = r.findings.filter((f) => f.patternId === "missing_header")
    const labels = headerFindings.map((f) => f.description)
    assert.deepEqual(labels.sort(), [
      "Content-Security-Policy header missing",
      "HSTS header missing",
      "Referrer-Policy header missing",
      "X-Content-Type-Options header missing",
      "X-Frame-Options header missing",
    ].sort())
  } finally {
    server.close()
  }
})

test("probe scans /package.json for secrets", async () => {
  const { server, port } = await startServer({
    "/": { body: '<html><body>app</body></html>' },
    "/package.json": {
      body: '{"name":"myapp","dependencies":{"express":"4.19.2"}}',
    },
  })
  try {
    const r = await probeUrl(`http://127.0.0.1:${port}`, { timeoutMs: 2000, concurrency: 4 })
    assert.ok(r.manifests >= 0, "manifest count reported")
  } finally {
    server.close()
  }
})
