import test from "node:test"
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { spawn } from "node:child_process"

function startServer(routes) {
  return new Promise((done) => {
    const server = createServer((req, res) => {
      const route = routes[req.url || "/"]
      if (!route) { res.writeHead(404).end(); return }
      res.writeHead(route.status ?? 200).end(route.body)
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

test("--report emits the ScanUrlAttach payload", async () => {
  const { server, port } = await startServer({
    "/.env": { body: "DATABASE_URL=postgres://u:" + "p@db/app\nSECRET=abc123def456\n" },
  })
  try {
    const { code, out } = await runCli(["scan", "--report", `http://127.0.0.1:${port}`])
    assert.equal(code, 0)
    const payload = JSON.parse(out)
    assert.equal(payload.url, `http://127.0.0.1:${port}`)
    assert.ok(Array.isArray(payload.findings))
    const env = payload.findings.find((f) => f.check_id === "exposed_env")
    assert.ok(env, "probe_env finding present")
    assert.equal(env.severity, "critical")
    assert.ok(!out.includes("abc123def456"), "payload must not leak raw values")
  } finally {
    server.close()
  }
})

test("--attach requires --api-key", async () => {
  const { server, port } = await startServer({})
  try {
    const { code, err } = await runCli(["scan", "--attach", "proj-1", `http://127.0.0.1:${port}`])
    assert.equal(code, 2)
    assert.ok(err.includes("--api-key"))
  } finally {
    server.close()
  }
})

test("--report on a dir target is rejected", async () => {
  const { code, err } = await runCli(["scan", "--report", "fixtures/clean"])
  assert.equal(code, 2)
  assert.ok(err.includes("URL target"))
})
