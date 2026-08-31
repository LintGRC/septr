import { describe, it, expect } from "vitest"
import http from "node:http"
import express from "express"
import { createSeptr } from "../adapters/express"
import type { AddressInfo } from "node:net"

function startServer(app: express.Express) {
  return new Promise<{ server: http.Server; port: number; close: () => Promise<void> }>((resolve) => {
    const server = http.createServer(app)
    server.listen(0, () => {
      const port = (server.address() as AddressInfo).port
      resolve({
        server,
        port,
        close: () => new Promise((resolve) => server.close(() => resolve())),
      })
    })
  })
}

describe("Express adapter — real HTTP", () => {
  function createTestApp(middleware: ReturnType<typeof createSeptr>) {
    const app = express()
    app.use(express.json())
    app.use(middleware)
    app.get("/data", (_req, res) => {
      res.json({ name: "John", password: "secret123" })
    })
    app.post("/data", (req, res) => {
      res.json(req.body)
    })
    app.get("/users/:userId", (_req, res) => {
      res.json({ ok: true })
    })
    return app
  }

  it("strips secrets from real Express JSON responses", async () => {
    const middleware = createSeptr({ secrets: true, bola: false, rateLimit: false })
    const app = createTestApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/data`)
      const body = await res.json()
      expect(body.password).toBe("[REDACTED]")
      expect(body.name).toBe("John")
      expect(res.headers.get("X-Septr-Stripped")).toBe("1")
    } finally {
      await close()
    }
  })

  it("blocks rate-limited requests with 429 on real Express", async () => {
    const middleware = createSeptr({
      rateLimit: true,
      rateLimitConfig: { max: 2, windowMs: 60000 },
      secrets: false,
      bola: false,
    })
    const app = createTestApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res1 = await fetch(`http://localhost:${port}/data`, { headers: { "x-forwarded-for": "1.2.3.4" } })
      expect(res1.status).toBe(200)

      const res2 = await fetch(`http://localhost:${port}/data`, { headers: { "x-forwarded-for": "1.2.3.4" } })
      expect(res2.status).toBe(200)

      const res3 = await fetch(`http://localhost:${port}/data`, { headers: { "x-forwarded-for": "1.2.3.4" } })
      expect(res3.status).toBe(429)
      const body = await res3.json()
      expect(body.error).toBe("Too many requests")
      expect(body.details).toEqual(expect.objectContaining({ type: "rate_limit", severity: "medium" }))
      expect(res3.headers.get("Retry-After")).toBeTruthy()
    } finally {
      await close()
    }
  })

  it("blocks sanitized input in POST on real Express", async () => {
    const middleware = createSeptr({
      inputSanitize: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
      bola: false,
    })
    const app = createTestApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/data`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "DROP TABLE users" }),
      })
      expect(res.status).toBe(400)
    } finally {
      await close()
    }
  })

  it("sanitizes query params on real Express", async () => {
    const middleware = createSeptr({
      inputSanitize: true,
      strictMode: true,
      rateLimit: false,
      secrets: false,
      bola: false,
    })
    const app = createTestApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/data?q=1+UNION+SELECT+*+FROM+users`)
      expect(res.status).toBe(400)
      const body = await res.json()
      expect(body.error).toContain("blocked")
    } finally {
      await close()
    }
  })

  it("selfTest returns true when middleware is mounted", async () => {
    const middleware = createSeptr({ secrets: true, bola: true, rateLimit: false })
    const app = createTestApp(middleware)
    const { server, close } = await startServer(app)

    try {
      const result = await middleware.selfTest(server)
      expect(result).toBe(true)
    } finally {
      await close()
    }
  })

  it("selfTest does not affect normal requests", async () => {
    const middleware = createSeptr({ secrets: true, bola: false, rateLimit: false })
    const app = createTestApp(middleware)
    const { server, port, close } = await startServer(app)

    try {
      await middleware.selfTest(server)

      const res = await fetch(`http://localhost:${port}/data`)
      expect(res.status).toBe(200)
      const body = await res.json()
      expect(body.name).toBe("John")
    } finally {
      await close()
    }
  })
})

const JWT_TENANT_123 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + "eyJ0ZW5hbnRfaWQiOiIxMjMiLCJz" + "dWIiOiI0MiJ9."

describe("Express adapter — tenant-aware", () => {
  function createTenantApp(middleware: ReturnType<typeof createSeptr>) {
    const app = express()
    app.use(express.json())
    app.use(middleware)
    app.get("/safe", (_req, res) => {
      res.json({ tenant_id: "123", name: "Safe" })
    })
    app.get("/leaked", (_req, res) => {
      res.json({ tenant_id: "456", name: "Cross-Tenant" })
    })
    app.get("/array-leak", (_req, res) => {
      res.json({
        todos: [
          { id: 1, tenant_id: "123" },
          { id: 2, tenant_id: "456" },
        ],
      })
    })
    return app
  }

  it("passes when response tenant matches JWT tenant", async () => {
    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id" },
    })
    const app = createTenantApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/safe`, {
        headers: { Authorization: `Bearer ${JWT_TENANT_123}` },
      })
      expect(res.status).toBe(200)
    } finally {
      await close()
    }
  })

  it("passes when no JWT token provided", async () => {
    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id" },
    })
    const app = createTenantApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/leaked`)
      expect(res.status).toBe(200)
    } finally {
      await close()
    }
  })

  it("does not block by default on leak (blockOnMismatch defaults to false)", async () => {
    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id" },
    })
    const app = createTenantApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/leaked`, {
        headers: { Authorization: `Bearer ${JWT_TENANT_123}` },
      })
      expect(res.status).toBe(200)
    } finally {
      await close()
    }
  })

  it("blocks when blockOnMismatch is true and tenant mismatches", async () => {
    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      ssrf: false,
      promptInjection: false,
      tamper: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id", blockOnMismatch: true },
    })
    const app = createTenantApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/leaked`, {
        headers: { Authorization: `Bearer ${JWT_TENANT_123}` },
      })
      expect(res.status).toBe(403)
      const body = await res.json()
      expect(body.error).toContain("Cross-tenant")
      expect(body.details.type).toBe("cross_tenant_leak")
    } finally {
      await close()
    }
  })

  it("detects leaks in nested arrays", async () => {
    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "tenant_id", blockOnMismatch: true },
    })
    const app = createTenantApp(middleware)
    const { port, close } = await startServer(app)

    try {
      const res = await fetch(`http://localhost:${port}/array-leak`, {
        headers: { Authorization: `Bearer ${JWT_TENANT_123}` },
      })
      expect(res.status).toBe(403)
    } finally {
      await close()
    }
  })

  it("works with custom tenant column name", async () => {
    function createOrgApp(middleware: ReturnType<typeof createSeptr>) {
      const app = express()
      app.use(express.json())
      app.use(middleware)
      app.get("/org", (_req, res) => {
        res.json({ org_id: "wrong-org", name: "Data" })
      })
      return app
    }

    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "org_id", jwtClaim: "org_id", blockOnMismatch: true },
    })
    const app = createOrgApp(middleware)
    const { port, close } = await startServer(app)

    const JWT_ORG = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + "eyJvcmdfaWQiOiJteS1vcmciLCJz" + "dWIiOiI0MiJ9."

    try {
      const res = await fetch(`http://localhost:${port}/org`, {
        headers: { Authorization: `Bearer ${JWT_ORG}` },
      })
      expect(res.status).toBe(403)
      const body = await res.json()
      expect(body.details.type).toBe("cross_tenant_leak")
    } finally {
      await close()
    }
  })

  it("works with nested JWT claim path", async () => {
    function createNestedApp(middleware: ReturnType<typeof createSeptr>) {
      const app = express()
      app.use(express.json())
      app.use(middleware)
      app.get("/nested", (_req, res) => {
        res.json({ tenant_id: "evil", name: "Data" })
      })
      return app
    }

    const middleware = createSeptr({
      rateLimit: false,
      secrets: false,
      bola: false,
      tenantAware: { tenantColumn: "tenant_id", jwtClaim: "app_metadata.tenant_id", blockOnMismatch: true },
    })
    const app = createNestedApp(middleware)
    const { port, close } = await startServer(app)

    const JWT_NESTED = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + "eyJhcHBfbWV0YWRhdGEiOnsidGVuYW50X2lkIjoiZ29vZCJ9LCJz" + "dWIiOiI0MiJ9."

    try {
      const res = await fetch(`http://localhost:${port}/nested`, {
        headers: { Authorization: `Bearer ${JWT_NESTED}` },
      })
      expect(res.status).toBe(403)
    } finally {
      await close()
    }
  })
})
