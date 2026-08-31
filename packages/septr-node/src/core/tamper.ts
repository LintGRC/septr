import type { DetectionEvent, FieldConstraint } from "./types"

const PRICING_FIELDS = [
  "amount", "price", "total", "cost", "value",
  "subtotal", "grand_total", "order_total", "payment_amount",
]

const QUANTITY_FIELDS = [
  "quantity", "qty", "count", "units", "items",
]

const PERMISSION_FIELDS = [
  "role", "admin", "isAdmin", "is_admin", "superadmin",
  "super_admin", "permissions", "privilege", "access_level",
  "user_role", "account_type", "plan", "tier",
]

const DISCOUNT_FIELDS = [
  "discount", "discount_percent", "discount_amount",
  "coupon", "promo", "promo_code", "voucher",
]

function toNumber(val: unknown): number | null {
  if (typeof val === "number") return val
  if (typeof val === "string") {
    const n = Number(val)
    if (!isNaN(n)) return n
  }
  return null
}

function detectSuspiciousPricing(body: Record<string, unknown>, route?: string, method?: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const now = Date.now()

  for (const field of PRICING_FIELDS) {
    const val = body[field]
    if (val === undefined) continue
    const num = toNumber(val)
    if (num === null) continue

    if (num < 0) {
      events.push({
        type: "business_logic_tamper",
        severity: "critical",
        patternId: "tamper_negative_amount",
        description: `Pricing field \`${field}\` has negative value ${num} — the server should reject negative amounts`,
        route,
        method,
        timestamp: now,
      })
    } else if (num === 0) {
      events.push({
        type: "business_logic_tamper",
        severity: "high",
        patternId: "tamper_zero_amount",
        description: `Pricing field \`${field}\` is zero — verify this is intentional and not client-side price manipulation`,
        route,
        method,
        timestamp: now,
      })
    }
  }

  for (const field of QUANTITY_FIELDS) {
    const val = body[field]
    if (val === undefined) continue
    const num = toNumber(val)
    if (num === null) continue

    if (num < 0) {
      events.push({
        type: "business_logic_tamper",
        severity: "critical",
        patternId: "tamper_negative_quantity",
        description: `Quantity field \`${field}\` has negative value ${num}`,
        route,
        method,
        timestamp: now,
      })
    }
  }

  for (const field of DISCOUNT_FIELDS) {
    const val = body[field]
    if (val === undefined) continue
    const num = toNumber(val)
    if (num === null) continue

    if (num >= 100) {
      events.push({
        type: "business_logic_tamper",
        severity: "critical",
        patternId: "tamper_full_discount",
        description: `Discount field \`${field}\` is ${num}% — a 100%+ discount means free product`,
        route,
        method,
        timestamp: now,
      })
    } else if (num < 0) {
      events.push({
        type: "business_logic_tamper",
        severity: "high",
        patternId: "tamper_negative_discount",
        description: `Discount field \`${field}\` has negative value ${num}%`,
        route,
        method,
        timestamp: now,
      })
    }
  }

  return events
}

function detectSuspiciousPermissions(body: Record<string, unknown>, route?: string, method?: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const now = Date.now()

  const privilegedValues = new Set([
    "admin", "superadmin", "super_admin", "owner", "root",
    "god", "sysadmin", "moderator", "mod", "staff",
  ])

  const booleanPrivilegeFields = new Set([
    "admin", "isAdmin", "is_admin", "superadmin", "super_admin",
    "isSuperAdmin", "is_super_admin", "isOwner", "is_owner",
    "staff", "isStaff", "is_staff", "moderator", "isModerator",
  ])

  for (const field of PERMISSION_FIELDS) {
    const val = body[field]
    if (val === undefined) continue

    if (typeof val === "boolean") {
      if (booleanPrivilegeFields.has(field) && val === true) {
        events.push({
          type: "business_logic_tamper",
          severity: "critical",
          patternId: "tamper_privilege_escalation",
          description: `Boolean privilege field \`${field}\` set to true in request body — permissions must be set server-side`,
          route,
          method,
          timestamp: now,
        })
      }
    } else if (typeof val === "string") {
      if (privilegedValues.has(val.toLowerCase())) {
        events.push({
          type: "business_logic_tamper",
          severity: "critical",
          patternId: "tamper_privilege_escalation",
          description: `Permission field \`${field}\` set to privileged value \`${val}\` in request body`,
          route,
          method,
          timestamp: now,
        })
      }
    }
  }

  return events
}

function validateConstraints(body: Record<string, unknown>, constraints: FieldConstraint[], route?: string, method?: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const now = Date.now()

  for (const { field, constraint } of constraints) {
    const val = body[field]

    switch (constraint.type) {
      case "readonly": {
        if (val !== undefined) {
          events.push({
            type: "business_logic_tamper",
            severity: "critical",
            patternId: "tamper_readonly_field",
            description: `Read-only field \`${field}\` was included in request body — remove it from client input`,
            route,
            method,
            timestamp: now,
          })
        }
        break
      }
      case "range": {
        if (val === undefined) break
        const num = toNumber(val)
        if (num === null) {
          events.push({
            type: "business_logic_tamper",
            severity: "high",
            patternId: "tamper_invalid_type",
            description: `Field \`${field}\` expected a number but got \`${typeof val}\``,
            route,
            method,
            timestamp: now,
          })
          break
        }
        if (constraint.min !== undefined && num < constraint.min) {
          events.push({
            type: "business_logic_tamper",
            severity: "high",
            patternId: "tamper_below_min",
            description: `Field \`${field}\` value ${num} is below minimum ${constraint.min}`,
            route,
            method,
            timestamp: now,
          })
        }
        if (constraint.max !== undefined && num > constraint.max) {
          events.push({
            type: "business_logic_tamper",
            severity: "high",
            patternId: "tamper_above_max",
            description: `Field \`${field}\` value ${num} is above maximum ${constraint.max}`,
            route,
            method,
            timestamp: now,
          })
        }
        break
      }
      case "enum": {
        if (val === undefined) break
        if (!constraint.values.includes(val as string | number)) {
          events.push({
            type: "business_logic_tamper",
            severity: "high",
            patternId: "tamper_invalid_enum",
            description: `Field \`${field}\` value \`${val}\` is not in allowed values: ${constraint.values.join(", ")}`,
            route,
            method,
            timestamp: now,
          })
        }
        break
      }
    }
  }

  return events
}

/** Detect client-side enforcement bypasses and business logic tampering.
 *
 * Two detection modes:
 * 1. **Auto-detection** (always runs): scans for suspicious pricing, quantity, discount,
 *    and permission fields in the request body without any configuration.
 * 2. **Constraint validation**: validates fields against user-declared constraints
 *    (readonly, range, enum) when `fieldConstraints` are provided in the config.
 *
 * Covers OWASP A04 (Insecure Design) — business logic flaws where the client
 * is trusted to enforce prices, permissions, or feature gates.
 *
 * **Limitations:**
 * - Cannot detect server-side trust of client-supplied IDs (use BOLA for that).
 * - Cannot verify that the server actually recalculates prices (requires code review).
 * - Auto-detection is heuristic — false positives possible on unusual field naming. */
export function detectBusinessLogicTamper(
  body: Record<string, unknown>,
  constraints?: FieldConstraint[],
  route?: string,
  method?: string,
): DetectionEvent[] {
  if (!body || typeof body !== "object") return []

  const events: DetectionEvent[] = []

  events.push(...detectSuspiciousPricing(body, route, method))
  events.push(...detectSuspiciousPermissions(body, route, method))

  if (constraints && constraints.length > 0) {
    events.push(...validateConstraints(body, constraints, route, method))
  }

  return events
}
