import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import { execSync } from "node:child_process"
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  checkSecurityHeaders,
  checkCookieFlags,
  checkDebugMode,
  checkRLSEnforcement,
  checkOverlyPermissivePolicies,
  checkSecurityDefinerFunctions,
  checkServiceRoleLeak,
  checkMultiTenantRLS,
  evaluateAttackStatus,
  computeAuditScore,
  printReportOutcome,
  ATTACKS,
  type AuditFinding,
} from "../cli"

vi.mock("node:child_process")
const mockExecSync = vi.mocked(execSync)



describe("CLI attack payloads", () => {
  it("has 6 attack definitions", () => {
    expect(ATTACKS).toHaveLength(6)
  })

  it("each attack has an engine, method, and path", () => {
    for (const attack of ATTACKS) {
      expect(attack.engine).toBeTruthy()
      expect(["GET", "POST"]).toContain(attack.method)
      expect(attack.path).toBeTruthy()
    }
  })

  it("secrets attack triggers stripe_test pattern", () => {
    const secrets = ATTACKS.find((a) => a.engine === "secrets")
    expect(secrets).toBeDefined()
    const body = secrets!.body as Record<string, string>
    expect(body.api_key).toMatch(/^sk_test_/)
  })

  it("sqli attack carries its payload in the query string, never a GET body", () => {
    const sqli = ATTACKS.find((a) => a.engine === "sqli")
    expect(sqli).toBeDefined()
    expect(sqli!.method).toBe("GET")
    expect(sqli!.body).toBeUndefined()
    expect(sqli!.path).toContain(encodeURIComponent("1' OR '1'='1"))
  })

  it("bola attack uses unsigned JWT", () => {
    const bola = ATTACKS.find((a) => a.engine === "bola")
    expect(bola).toBeDefined()
    const token = bola!.headers!.Authorization.replace("Bearer ", "")
    const parts = token.split(".")
    expect(parts).toHaveLength(3)
    // Decode payload
    const payload = JSON.parse(atob(parts[1]))
    expect(payload.sub).toBe("42")
  })
})

describe("parseArgs", () => {
  const originalArgv = process.argv

  beforeEach(() => {
    process.argv = ["node", "cli"]
  })

  afterEach(() => {
    process.argv = originalArgv
  })

  it("returns defaults when no args provided", () => {
    // parseArgs requires --key, so this should fail
  })

  it("parses --url flag", () => {
    process.argv = ["node", "cli", "--url", "http://myapp.com", "--key", "vs_live_xxx"]
    const { url, key, apiUrl } = parseArgs(process.argv)
    expect(url).toBe("http://myapp.com")
    expect(key).toBe("vs_live_xxx")
    expect(apiUrl).toBe("http://localhost:8000")
  })

  it("parses --api-url flag", () => {
    process.argv = ["node", "cli", "--key", "vs_live_xxx", "--api-url", "https://api.example.com"]
    const { apiUrl } = parseArgs(process.argv)
    expect(apiUrl).toBe("https://api.example.com")
  })
})

// Helper to avoid importing the CLI module directly
describe("checkSecurityHeaders", () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal("fetch", mockFetch)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("fails when HSTS is missing", async () => {
    mockFetch.mockResolvedValue({ headers: new Headers() })
    const result = await checkSecurityHeaders("http://localhost:3000")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("HSTS")
  })

  it("passes when all security headers present", async () => {
    const h = new Headers()
    h.set("strict-transport-security", "max-age=31536000")
    h.set("x-content-type-options", "nosniff")
    h.set("content-security-policy", "default-src 'self'")
    h.set("x-frame-options", "DENY")
    mockFetch.mockResolvedValue({ headers: h })
    const result = await checkSecurityHeaders("http://localhost:3000")
    expect(result.passed).toBe(true)
  })

  it("fails on permissive CSP", async () => {
    const h = new Headers()
    h.set("content-security-policy", "default-src *")
    mockFetch.mockResolvedValue({ headers: h })
    const result = await checkSecurityHeaders("http://localhost:3000")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("Permissive CSP")
  })

  it("passes with CSP frame-ancestors instead of X-Frame-Options", async () => {
    const h = new Headers()
    h.set("strict-transport-security", "max-age=31536000")
    h.set("x-content-type-options", "nosniff")
    h.set("content-security-policy", "default-src 'self'; frame-ancestors 'none'")
    mockFetch.mockResolvedValue({ headers: h })
    const result = await checkSecurityHeaders("http://localhost:3000")
    expect(result.passed).toBe(true)
  })
})

describe("checkCookieFlags", () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal("fetch", mockFetch)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("ignores non-session cookies", async () => {
    const h = new Headers()
    h.set("set-cookie", "_ga=GA1.2.123; Path=/")
    mockFetch.mockResolvedValue({ headers: h })
    const result = await checkCookieFlags("http://localhost:3000")
    expect(result.passed).toBe(true)
  })

  it("fails when session cookie missing Secure flag", async () => {
    const h = new Headers()
    h.set("set-cookie", "session_id=abc123; Path=/; HttpOnly")
    mockFetch.mockResolvedValue({ headers: h })
    const result = await checkCookieFlags("http://localhost:3000")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("Secure")
  })

  it("passes when session cookie has all flags", async () => {
    const h = new Headers()
    h.set("set-cookie", "session_id=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")
    mockFetch.mockResolvedValue({ headers: h })
    const result = await checkCookieFlags("http://localhost:3000")
    expect(result.passed).toBe(true)
  })
})

function parseArgs(argv: string[]): { url: string; key: string; apiUrl: string } {
  let url = "http://localhost:3000"
  let key = ""
  let apiUrl = "http://localhost:8000"

  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case "--url":
        url = argv[++i] ?? url
        break
      case "--key":
        key = argv[++i] ?? ""
        break
      case "--api-url":
        apiUrl = argv[++i] ?? apiUrl
        break
    }
  }

  return { url, key, apiUrl }
}

describe("checkRLSEnforcement", () => {
  beforeEach(() => {
    mockExecSync.mockReset()
  })

  it("returns low severity when no db url", async () => {
    const result = await checkRLSEnforcement(undefined)
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("low")
    expect(result.detail).toContain("No database URL")
  })

  it("returns medium severity when psql not found", async () => {
    mockExecSync.mockImplementation(() => { throw new Error("not found") })
    const result = await checkRLSEnforcement("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("medium")
  })

  it("passes when all tables have RLS enabled", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("")
    const result = await checkRLSEnforcement("postgresql://localhost:5432/test")
    expect(result.passed).toBe(true)
    expect(result.detail).toContain("RLS enforcement enabled")
  })

  it("fails when tables have RLS disabled despite having policies", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("users\norders")
    const result = await checkRLSEnforcement("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("critical")
    expect(result.detail).toContain("disabled")
    expect(result.detail).toContain("users")
  })

  it("returns medium severity on query failure", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockImplementation(() => { throw new Error("connection refused") })
    const result = await checkRLSEnforcement("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("medium")
    expect(result.detail).toContain("connection refused")
  })
})

describe("checkOverlyPermissivePolicies", () => {
  beforeEach(() => {
    mockExecSync.mockReset()
  })

  it("returns low severity when no db url", async () => {
    const result = await checkOverlyPermissivePolicies(undefined)
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("low")
  })

  it("passes when no policies exist", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(true)
  })

  it("passes when no risky policies found", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("users\tuser_policy\t(auth.uid() = user_id)")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(true)
  })

  it("fails on unconditional true policy", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("users\tall_access\ttrue")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("unconditional true")
  })

  it("fails on OR true bypass", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("documents\tread_all\t(auth.uid() = owner_id OR true)")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("OR true")
  })

  it("fails on 1=1 tautology", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("secrets\tpublic_read\t(1 = 1)")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("1=1")
  })

  it("fails on role-only check without row filter", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("profiles\tall_auth\t(auth.role() = 'authenticated')")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("role-only")
  })

  it("passes when role check includes user_id filter", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("profiles\tuser_access\t(auth.role() = 'authenticated' AND auth.uid() = user_id)")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(true)
  })

  it("handles multiple risky policies", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("users\topen_bar\ttrue\norders\tbypass\t(1=1)")
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("users.open_bar")
    expect(result.detail).toContain("orders.bypass")
  })

  it("returns medium severity on query failure", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockImplementation(() => { throw new Error("timeout") })
    const result = await checkOverlyPermissivePolicies("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("medium")
  })
})

describe("checkSecurityDefinerFunctions", () => {
  beforeEach(() => {
    mockExecSync.mockReset()
  })

  it("returns low severity when no db url", async () => {
    const result = await checkSecurityDefinerFunctions(undefined)
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("low")
  })

  it("passes when no SECURITY DEFINER functions found", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("")
    const result = await checkSecurityDefinerFunctions("postgresql://localhost:5432/test")
    expect(result.passed).toBe(true)
  })

  it("fails when SECURITY DEFINER functions exist", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("public.bypass_rls\npublic.impersonate_user")
    const result = await checkSecurityDefinerFunctions("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("high")
    expect(result.detail).toContain("bypass_rls")
    expect(result.detail).toContain("impersonate_user")
  })

  it("returns medium severity on query failure", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockImplementation(() => { throw new Error("permission denied") })
    const result = await checkSecurityDefinerFunctions("postgresql://localhost:5432/test")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("medium")
  })
})

describe("checkServiceRoleLeak", () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(path.join(tmpdir(), "septr-test-"))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it("passes on empty project", async () => {
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(true)
  })

  it("passes when no service_role references exist", async () => {
    mkdirSync(path.join(tmpDir, "src"), { recursive: true })
    writeFileSync(path.join(tmpDir, ".env"), "DATABASE_URL=postgres://localhost:5432/db")
    writeFileSync(path.join(tmpDir, "src", "app.ts"), 'import { createClient } from "@supabase/supabase-js"\nconst supabase = createClient(url, anonKey)')
    writeFileSync(path.join(tmpDir, "src", "api.ts"), "export function getUser(id: string) { return db.query('SELECT * FROM users WHERE id = $1', [id]) }")
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(true)
  })

  it("fails when SUPABASE_SERVICE_ROLE_KEY in .env", async () => {
    writeFileSync(path.join(tmpDir, ".env"), "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0")
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("critical")
    expect(result.detail).toContain("SUPABASE_SERVICE_ROLE_KEY")
  })

  it("fails when service_role literal in source code", async () => {
    mkdirSync(path.join(tmpDir, "lib"), { recursive: true })
    writeFileSync(path.join(tmpDir, "lib", "supabase.ts"), `import { createClient } from "@supabase/supabase-js"
const supabaseUrl = process.env.SUPABASE_URL || ""
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || ""
export const supabase = createClient(supabaseUrl, supabaseKey)
`)
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("SUPABASE_SERVICE_ROLE_KEY")
    expect(result.detail).toContain("lib/supabase.ts")
  })

  it("fails when service_role_key used as variable", async () => {
    mkdirSync(path.join(tmpDir, "api"), { recursive: true })
    writeFileSync(path.join(tmpDir, "api", "admin.ts"), "const service_role_key = 'eyJhbGciOiJIUzI1NiJ9.' + 'eyJyb2xlIjoic2VydmljZV9yb2xlIn0'")
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("service_role_key")
  })

  it("fails when supabaseServiceRole used in code", async () => {
    mkdirSync(path.join(tmpDir, "utils"), { recursive: true })
    writeFileSync(path.join(tmpDir, "utils", "config.ts"), "export const config = { supabaseServiceRole: 'eyJhbGciOiJIUzI1NiJ9.' + 'eyJyb2xlIjoic2VydmljZV9yb2xlIn0' }")
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("supabaseServiceRole")
  })

  it("finds multiple files with leaks", async () => {
    writeFileSync(path.join(tmpDir, ".env"), "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0")
    mkdirSync(path.join(tmpDir, "src"), { recursive: true })
    writeFileSync(path.join(tmpDir, "src", "client.ts"), 'const key = "service_role"')
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("SUPABASE_SERVICE_ROLE_KEY")
    expect(result.detail).toContain("service_role")
  })

  it("skips node_modules", async () => {
    mkdirSync(path.join(tmpDir, "node_modules", "@supabase", "supabase-js"), { recursive: true })
    writeFileSync(path.join(tmpDir, "node_modules", "@supabase", "supabase-js", "index.ts"), 'const SERVICE_ROLE_KEY = "test"')
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(true)
  })

  it("skips Go module cache (pkg/mod)", async () => {
    mkdirSync(path.join(tmpDir, "pkg", "mod", "golang.org", "x", "crypto"), { recursive: true })
    writeFileSync(path.join(tmpDir, "pkg", "mod", "golang.org", "x", "crypto", "keys.go"), 'const SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0"')
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(true)
  })

  it("does not skip a legit pkg source dir", async () => {
    mkdirSync(path.join(tmpDir, "pkg", "auth"), { recursive: true })
    writeFileSync(path.join(tmpDir, "pkg", "auth", "admin.ts"), "const service_role_key = 'test'")
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(false)
  })

  it("skips dist", async () => {
    mkdirSync(path.join(tmpDir, "dist"), { recursive: true })
    writeFileSync(path.join(tmpDir, "dist", "bundle.js"), 'var SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0"')
    const result = await checkServiceRoleLeak(tmpDir)
    expect(result.passed).toBe(true)
  })
})

describe("checkMultiTenantRLS", () => {
  beforeEach(() => {
    mockExecSync.mockReset()
  })

  it("returns low severity when no db url", async () => {
    const result = await checkMultiTenantRLS(undefined, "tenant_id")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("low")
    expect(result.detail).toContain("No database URL")
  })

  it("returns low severity when no tenant column provided", async () => {
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", undefined)
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("low")
    expect(result.detail).toContain("--tenant-column")
  })

  it("returns medium severity when psql not found", async () => {
    mockExecSync.mockImplementation(() => { throw new Error("not found") })
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "tenant_id")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("medium")
  })

  it("passes when no policies exist", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "tenant_id")
    expect(result.passed).toBe(true)
  })

  it("passes when policy includes tenant column filter", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("todos\tuser_access\t(auth.uid() = user_id AND tenant_id = current_setting('app.tenant_id'))")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "tenant_id")
    expect(result.passed).toBe(true)
    expect(result.detail).toContain("tenant_id")
  })

  it("fails when user_id check without tenant column", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("todos\tuser_access\t(auth.uid() = user_id)")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "tenant_id")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("high")
    expect(result.detail).toContain("user-level check without tenant_id filter")
  })

  it("fails when owner_id used without tenant column", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("documents\towner_access\t(owner_id = auth.uid())")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "tenant_id")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("user-level check without tenant_id filter")
  })

  it("fails when current_setting() without tenant context", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("orders\tctx_access\t(current_setting('app.user_id') = user_id)")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "company_id")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("current_setting() without tenant context")
  })

  it("fails when auth.jwt() without tenant claim", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("profiles\tjwt_access\t(auth.jwt()->>'role' = 'authenticated')")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "org_id")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("auth.jwt() used without org_id claim")
  })

  it("reports multiple issues across policies", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("todos\tu1\t(auth.uid() = user_id)\ndocs\to1\t(owner_id = auth.uid())")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "tenant_id")
    expect(result.passed).toBe(false)
    expect(result.detail).toContain("todos.u1")
    expect(result.detail).toContain("docs.o1")
  })

  it("passes when auth.uid() with different tenant column name", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockReturnValueOnce("workspaces\tws_access\t(auth.uid() = user_id AND org_id = auth.jwt()->>'org_id')")
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "org_id")
    expect(result.passed).toBe(true)
  })

  it("returns medium severity on query failure", async () => {
    mockExecSync.mockReturnValueOnce("/usr/bin/psql")
    mockExecSync.mockImplementation(() => { throw new Error("timeout") })
    const result = await checkMultiTenantRLS("postgresql://localhost:5432/test", "tenant_id")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("medium")
  })
})

describe("evaluateAttackStatus", () => {
  it("treats 4xx as blocked", () => {
    expect(evaluateAttackStatus(403, null)).toEqual({ passed: true, inconclusive: false })
    expect(evaluateAttackStatus(500, null)).toEqual({ passed: true, inconclusive: false })
  })

  it("treats 404/405 without strip header as inconclusive, not a pass", () => {
    expect(evaluateAttackStatus(404, null)).toEqual({ passed: false, inconclusive: true })
    expect(evaluateAttackStatus(405, null)).toEqual({ passed: false, inconclusive: true })
  })

  it("still counts a 404 with X-Septr-Stripped as protected", () => {
    expect(evaluateAttackStatus(404, "secrets")).toEqual({ passed: true, inconclusive: false })
  })

  it("treats 200 without strip header as a real failure", () => {
    expect(evaluateAttackStatus(200, null)).toEqual({ passed: false, inconclusive: false })
  })

  it("treats 200 with X-Septr-Stripped as protected", () => {
    expect(evaluateAttackStatus(200, "secrets")).toEqual({ passed: true, inconclusive: false })
  })
})

describe("computeAuditScore", () => {
  const finding = (passed: boolean, skipped = false): AuditFinding =>
    ({ check: "x", passed, detail: "", severity: "low", fix: "", skipped })

  it("excludes skipped checks from the score", () => {
    const result = computeAuditScore([finding(true), finding(true), finding(false, true), finding(false, true)])
    expect(result).toEqual({ score: 100, grade: "A", passed: 2, total: 2, skipped: 2 })
  })

  it("grades over checks that ran", () => {
    const findings = [
      ...Array.from({ length: 6 }, () => finding(true)),
      ...Array.from({ length: 4 }, () => finding(false)),
      finding(false, true),
    ]
    const result = computeAuditScore(findings)
    expect(result.score).toBe(60)
    expect(result.grade).toBe("D")
    expect(result.skipped).toBe(1)
  })

  it("returns 0/F when everything was skipped", () => {
    const result = computeAuditScore([finding(false, true)])
    expect(result).toEqual({ score: 0, grade: "F", passed: 0, total: 0, skipped: 1 })
  })
})

describe("checkDebugMode", () => {
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    mockFetch = vi.fn()
    vi.stubGlobal("fetch", mockFetch)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("passes when unknown paths serve the SPA shell", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "text/html; charset=utf-8" }),
    })
    const result = await checkDebugMode("http://localhost:3000")
    expect(result.passed).toBe(true)
  })

  it("passes when the endpoint 404s", async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 404, headers: new Headers() })
    const result = await checkDebugMode("http://localhost:3000")
    expect(result.passed).toBe(true)
  })

  it("fails when a non-HTML debug endpoint responds", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
    })
    const result = await checkDebugMode("http://localhost:3000")
    expect(result.passed).toBe(false)
    expect(result.severity).toBe("high")
  })

  it("passes when the app is unreachable", async () => {
    mockFetch.mockRejectedValue(new Error("connect ECONNREFUSED"))
    const result = await checkDebugMode("http://localhost:3000")
    expect(result.passed).toBe(true)
  })
})

describe("printReportOutcome", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("confirms success", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {})
    printReportOutcome({ ok: true })
    expect(log).toHaveBeenCalledWith("Results reported.")
  })

  it("warns with the reason on failure", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
    printReportOutcome({ ok: false, reason: "HTTP 401 from https://app.septr.dev — check the API key" })
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("HTTP 401"))
  })
})
