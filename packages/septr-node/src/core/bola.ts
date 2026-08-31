import type { DetectionEvent } from "./types"

const PARAM_PATTERNS = [
  /\/:([a-zA-Z_][a-zA-Z0-9_]*)/g,
  /\/(\{[a-zA-Z_][a-zA-Z0-9_]*\})/g,
  /\/(\[[a-zA-Z_][a-zA-Z0-9_]*\])/g,
  /\/<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>/g,
]

const PARAM_SEGMENT_PATTERNS = [
  /^:([a-zA-Z_][a-zA-Z0-9_]*)$/,
  /^\{([a-zA-Z_][a-zA-Z0-9_]*)\}$/,
  /^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$/,
  /^<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>$/,
]

const BODY_ID_FIELDS = [
  "userId", "user_id",
  "ownerId", "owner_id",
  "createdBy", "created_by",
  "accountId", "account_id",
  "customerId", "customer_id",
  "employeeId", "employee_id",
  "studentId", "student_id",
  "patientId", "patient_id",
  "memberId", "member_id",
]

/** Extract dynamic route parameters from a URL pattern (supports Express `:param`, Hono `:param`, and `{param}` formats). */
export function extractRouteParams(path: string): string[] {
  const params: string[] = []

  for (const pattern of PARAM_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags)
    let match = regex.exec(path)

    while (match !== null) {
      const param = match[1].replace(/[{}[\]]/g, "")
      params.push(param)
      match = regex.exec(path)
    }
  }

  return params
}

function paramName(segment: string): string | null {
  for (const pattern of PARAM_SEGMENT_PATTERNS) {
    const match = pattern.exec(segment)
    if (match) return match[1]
  }
  return null
}

/** Find the route template (e.g. `/api/users/:userId`) that structurally matches the concrete request path. */
export function matchRouteTemplate(path: string, templates: string[]): string | null {
  const pathSegments = path.replace(/\/+$/, "").split("/").filter(Boolean)
  for (const template of templates) {
    const tSegments = template.replace(/\/+$/, "").split("/").filter(Boolean)
    if (tSegments.length !== pathSegments.length) continue
    let matched = true
    for (let i = 0; i < tSegments.length; i++) {
      if (paramName(tSegments[i]) !== null) continue
      if (tSegments[i] !== pathSegments[i]) {
        matched = false
        break
      }
    }
    if (matched) return template
  }
  return null
}

/** Extract the actual values of dynamic route params from a concrete path, using the route template. */
export function extractRouteParamValues(template: string, path: string): Record<string, string> {
  const values: Record<string, string> = {}
  const tSegments = template.replace(/\/+$/, "").split("/").filter(Boolean)
  const pSegments = path.replace(/\/+$/, "").split("/").filter(Boolean)
  if (tSegments.length !== pSegments.length) return values
  for (let i = 0; i < tSegments.length; i++) {
    const name = paramName(tSegments[i])
    if (name !== null) values[name] = pSegments[i]
  }
  return values
}

function base64UrlDecode(str: string): string {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/")
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4)
  return atob(padded)
}

/** Decode a JWT token and extract all claims. Works in Edge runtimes (no Buffer dependency). */
export function extractTokenClaims(token: string): Record<string, unknown> {
  const claims: Record<string, unknown> = {}

  try {
    const parts = token.split(".")
    if (parts.length !== 3) return claims

    const payload = JSON.parse(base64UrlDecode(parts[1]))

    for (const [key, value] of Object.entries(payload)) {
      if (value !== undefined && value !== null) {
        claims[key] = value
      }
    }
  } catch {
    // invalid token
  }

  return claims
}

/** Detect BOLA/IDOR violations by comparing route params and body fields against the authenticated user's token claims.
 *
 * **Heuristic approach:** This uses convention-over-configuration matching — it checks common route param
 * names (`:userId`, `:id`, `:ownerId`, etc.) against standard JWT claims (`sub`, `user_id`, `id`).
 *
 * When `routeParamValues` (the actual values extracted from the request path) is provided, the
 * comparison is value-based: a request to `/api/users/42` with `sub=42` is legitimate, while
 * `/api/users/999` with `sub=42` is flagged. Without values, detection falls back to presence-based
 * flagging of ID-named params (advisory).
 *
 * **Limitations:**
 * - Nested routes like `/orgs/:orgId/projects/:projectId/users/:userId` may produce false positives
 *   (only the final param is checked against token claims).
 * - Role-based tokens with `tenant_id`, `org_id`, or custom scopes are not matched.
 * - Complex RBAC/ABAC logic requires application-level enforcement.
 * - Integer vs UUID ID formats are compared as strings.
 *
 * Use this as a first-pass guard. For full access control, implement authorization at the application layer. */
export function detectBOLA(
  routeParams: string[],
  bodyParams: Record<string, string> | null,
  tokenClaims: Record<string, unknown>,
  route?: string,
  method?: string,
  routeParamValues?: Record<string, string>,
): DetectionEvent | null {
  const tokenUserId = (tokenClaims.sub || tokenClaims.user_id || tokenClaims.userId || tokenClaims.id || tokenClaims.account_id || tokenClaims.owner_id) as string | undefined

  if (!tokenUserId) return null

  if (routeParamValues) {
    for (const [param, value] of Object.entries(routeParamValues)) {
      if (BODY_ID_FIELDS.includes(param) && value !== tokenUserId) {
        return {
          type: "bola",
          severity: "high",
          patternId: "bola_param_mismatch",
          description: `Route param \`${param}=${value}\` does not match authenticated user \`${tokenUserId}\``,
          route,
          method,
          timestamp: Date.now(),
        }
      }
    }
  }

  for (const param of routeParams) {
    if (BODY_ID_FIELDS.includes(param) && (!routeParamValues || !(param in routeParamValues))) {
      return {
        type: "bola",
        severity: "high",
        patternId: "bola_param_mismatch",
        description: `Route param \`${param}\` may be manipulable`,
        route,
        method,
        timestamp: Date.now(),
      }
    }
  }

  if (bodyParams) {
    for (const field of BODY_ID_FIELDS) {
      if (bodyParams[field] && bodyParams[field] !== tokenUserId) {
        return {
          type: "bola",
          severity: "critical",
          patternId: "bola_body_mismatch",
          description: `Body field \`${field}\` does not match authenticated user`,
          route,
          method,
          timestamp: Date.now(),
        }
      }
    }
  }

  return null
}
