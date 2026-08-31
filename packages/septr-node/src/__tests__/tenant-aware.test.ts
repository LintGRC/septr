import { describe, it, expect } from "vitest"
import { extractTenantFromJwt, detectCrossTenantLeaks } from "../core/tenant-aware"

describe("extractTenantFromJwt", () => {
  it("returns null when claims are null", () => {
    expect(extractTenantFromJwt(null, "tenant_id")).toBeNull()
  })

  it("extracts top-level claim", () => {
    const claims = { tenant_id: "123", sub: "user-1" }
    expect(extractTenantFromJwt(claims, "tenant_id")).toBe("123")
  })

  it("extracts nested claim via dot-path", () => {
    const claims = { app_metadata: { tenant_id: "456" }, sub: "user-2" }
    expect(extractTenantFromJwt(claims, "app_metadata.tenant_id")).toBe("456")
  })

  it("extracts deeply nested claim", () => {
    const claims = { user: { org: { tenant_id: "789" } } }
    expect(extractTenantFromJwt(claims, "user.org.tenant_id")).toBe("789")
  })

  it("returns null when claim not found", () => {
    const claims = { sub: "user-3" }
    expect(extractTenantFromJwt(claims, "tenant_id")).toBeNull()
  })

  it("returns null when intermediate path is missing", () => {
    const claims = { sub: "user-4" }
    expect(extractTenantFromJwt(claims, "app_metadata.tenant_id")).toBeNull()
  })

  it("converts numeric value to string", () => {
    const claims = { tenant_id: 42 }
    expect(extractTenantFromJwt(claims, "tenant_id")).toBe("42")
  })
})

describe("detectCrossTenantLeaks", () => {
  it("returns empty for empty object", () => {
    expect(detectCrossTenantLeaks("tenant-1", {}, "tenant_id")).toEqual([])
  })

  it("returns empty for null", () => {
    expect(detectCrossTenantLeaks("tenant-1", null, "tenant_id")).toEqual([])
  })

  it("returns empty when tenant column matches", () => {
    const body = { tenant_id: "tenant-1", name: "Test" }
    expect(detectCrossTenantLeaks("tenant-1", body, "tenant_id")).toEqual([])
  })

  it("returns leak when tenant column mismatches", () => {
    const body = { tenant_id: "tenant-2", name: "Test" }
    const leaks = detectCrossTenantLeaks("tenant-1", body, "tenant_id")
    expect(leaks).toHaveLength(1)
    expect(leaks[0].path).toBe("tenant_id")
    expect(leaks[0].value).toBe("tenant-2")
  })

  it("detects leak in nested object", () => {
    const body = { data: { tenant_id: "evil-corp", name: "Secret" } }
    const leaks = detectCrossTenantLeaks("my-company", body, "tenant_id")
    expect(leaks).toHaveLength(1)
    expect(leaks[0].path).toBe("data.tenant_id")
    expect(leaks[0].value).toBe("evil-corp")
  })

  it("detects leaks in array of objects", () => {
    const body = {
      todos: [
        { id: 1, tenant_id: "tenant-a" },
        { id: 2, tenant_id: "tenant-a" },
      ],
    }
    const leaks = detectCrossTenantLeaks("tenant-b", body, "tenant_id")
    expect(leaks).toHaveLength(2)
    expect(leaks[0].path).toBe("todos[0].tenant_id")
    expect(leaks[1].path).toBe("todos[1].tenant_id")
  })

  it("reports only mismatching items in arrays", () => {
    const body = {
      items: [
        { id: 1, tenant_id: "mine" },
        { id: 2, tenant_id: "theirs" },
        { id: 3, tenant_id: "mine" },
      ],
    }
    const leaks = detectCrossTenantLeaks("mine", body, "tenant_id")
    expect(leaks).toHaveLength(1)
    expect(leaks[0].value).toBe("theirs")
  })

  it("returns empty when column not present", () => {
    const body = { id: 1, name: "Test", user_id: "42" }
    expect(detectCrossTenantLeaks("tenant-1", body, "tenant_id")).toEqual([])
  })

  it("skips null/undefined tenant values", () => {
    const body = { tenant_id: null, other: { tenant_id: undefined } }
    expect(detectCrossTenantLeaks("tenant-1", body, "tenant_id")).toEqual([])
  })

  it("matches numeric tenant ids as strings", () => {
    const body = { tenant_id: "42" }
    expect(detectCrossTenantLeaks("42", body, "tenant_id")).toEqual([])
  })

  it("reports mismatch with numeric vs string comparison", () => {
    const body = { tenant_id: 42 }
    expect(detectCrossTenantLeaks("42", body, "tenant_id")).toEqual([])
  })

  it("detects deeply nested mismatch", () => {
    const body = {
      level1: {
        level2: {
          level3: { tenant_id: "wrong" },
        },
      },
    }
    const leaks = detectCrossTenantLeaks("correct", body, "tenant_id")
    expect(leaks).toHaveLength(1)
    expect(leaks[0].path).toBe("level1.level2.level3.tenant_id")
  })

  it("uses custom column name", () => {
    const body = { org_id: "evil-corp", name: "Test" }
    const leaks = detectCrossTenantLeaks("my-org", body, "org_id")
    expect(leaks).toHaveLength(1)
    expect(leaks[0].value).toBe("evil-corp")
  })

  it("handles mixed array with and without tenant column", () => {
    const body = {
      items: [
        { id: 1, name: "Safe" },
        { id: 2, tenant_id: "theirs" },
        { id: 3, name: "Also safe" },
      ],
    }
    const leaks = detectCrossTenantLeaks("mine", body, "tenant_id")
    expect(leaks).toHaveLength(1)
    expect(leaks[0].value).toBe("theirs")
  })
})
