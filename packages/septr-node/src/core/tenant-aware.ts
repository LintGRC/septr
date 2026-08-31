import type { TenantAwareConfig } from "./types"

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".")
  let current: unknown = obj
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") return undefined
    current = (current as Record<string, unknown>)[part]
  }
  return current
}

export function extractTenantFromJwt(
  claims: Record<string, unknown> | null,
  jwtClaim: string,
): string | null {
  if (!claims) return null
  const value = getNestedValue(claims, jwtClaim)
  if (value === null || value === undefined) return null
  return String(value)
}

export interface TenantLeak {
  path: string
  value: unknown
}

export function detectCrossTenantLeaks(
  expectedTenantId: string,
  body: unknown,
  tenantColumn: string,
): TenantLeak[] {
  const leaks: TenantLeak[] = []

  function scan(obj: unknown, path: string): void {
    if (obj === null || obj === undefined) return
    if (typeof obj !== "object") return

    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) {
        scan(obj[i], `${path}[${i}]`)
      }
      return
    }

    const record = obj as Record<string, unknown>
    for (const key of Object.keys(record)) {
      const currentPath = path ? `${path}.${key}` : key
      const value = record[key]

      if (key === tenantColumn && value !== null && value !== undefined) {
        if (String(value) !== expectedTenantId) {
          leaks.push({ path: currentPath, value })
        }
        continue
      }

      if (typeof value === "object" && value !== null) {
        scan(value, currentPath)
      }
    }
  }

  scan(body, "")
  return leaks
}

export function createTenantCheckResponse(
  tenantId: string,
  body: unknown,
  config: TenantAwareConfig,
): { blocked: boolean; leaks: TenantLeak[] } {
  const leaks = detectCrossTenantLeaks(tenantId, body, config.tenantColumn)
  if (leaks.length > 0 && config.blockOnMismatch) {
    return { blocked: true, leaks }
  }
  return { blocked: false, leaks }
}
