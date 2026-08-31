import { describe, it, expect } from "vitest"
import { detectBusinessLogicTamper } from "../../core/tamper"
import type { DetectionEvent } from "../../core/types"

interface TamperPayload {
  body: Record<string, unknown>
  expect: boolean
  patternId?: string
  source: string
}

const tamperPayloads: TamperPayload[] = [
  // === Negative amounts ===
  { body: { amount: -100 }, expect: true, patternId: "tamper_negative_amount", source: "negative amount" },
  { body: { price: -50 }, expect: true, patternId: "tamper_negative_amount", source: "negative price" },
  { body: { total: -999 }, expect: true, patternId: "tamper_negative_amount", source: "negative total" },
  { body: { cost: -1 }, expect: true, patternId: "tamper_negative_amount", source: "negative cost" },
  { body: { value: -25 }, expect: true, patternId: "tamper_negative_amount", source: "negative value" },
  { body: { subtotal: -500 }, expect: true, patternId: "tamper_negative_amount", source: "negative subtotal" },
  { body: { grand_total: -1000 }, expect: true, patternId: "tamper_negative_amount", source: "negative grand_total" },
  { body: { payment_amount: -25 }, expect: true, patternId: "tamper_negative_amount", source: "negative payment_amount" },
  { body: { amount: "-100" }, expect: true, patternId: "tamper_negative_amount", source: "string negative amount" },

  // === Zero amounts ===
  { body: { amount: 0 }, expect: true, patternId: "tamper_zero_amount", source: "zero amount" },
  { body: { price: 0 }, expect: true, patternId: "tamper_zero_amount", source: "zero price" },
  { body: { total: 0 }, expect: true, patternId: "tamper_zero_amount", source: "zero total" },
  { body: { amount: "0" }, expect: true, patternId: "tamper_zero_amount", source: "string zero amount" },

  // === Negative quantities ===
  { body: { quantity: -5 }, expect: true, patternId: "tamper_negative_quantity", source: "negative quantity" },
  { body: { qty: -1 }, expect: true, patternId: "tamper_negative_quantity", source: "negative qty" },
  { body: { count: -10 }, expect: true, patternId: "tamper_negative_quantity", source: "negative count" },

  // === Discount abuse ===
  { body: { discount: 100 }, expect: true, patternId: "tamper_full_discount", source: "100% discount" },
  { body: { discount_percent: 200 }, expect: true, patternId: "tamper_full_discount", source: "200% discount" },
  { body: { discount: 150 }, expect: true, patternId: "tamper_full_discount", source: "150% discount" },
  { body: { discount: -50 }, expect: true, patternId: "tamper_negative_discount", source: "negative discount" },
  { body: { promo: -25 }, expect: true, patternId: "tamper_negative_discount", source: "negative promo" },

  // === Privilege escalation ===
  { body: { isAdmin: true }, expect: true, patternId: "tamper_privilege_escalation", source: "isAdmin: true" },
  { body: { is_admin: true }, expect: true, patternId: "tamper_privilege_escalation", source: "is_admin: true" },
  { body: { superadmin: true }, expect: true, patternId: "tamper_privilege_escalation", source: "superadmin: true" },
  { body: { role: "admin" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: admin" },
  { body: { role: "superadmin" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: superadmin" },
  { body: { role: "owner" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: owner" },
  { body: { role: "root" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: root" },
  { body: { role: "moderator" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: moderator" },
  { body: { role: "staff" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: staff" },
  { body: { role: "sysadmin" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: sysadmin" },
  { body: { role: "god" }, expect: true, patternId: "tamper_privilege_escalation", source: "role: god" },
  { body: { plan: "admin" }, expect: true, patternId: "tamper_privilege_escalation", source: "plan: admin" },
  { body: { user_role: "super_admin" }, expect: true, patternId: "tamper_privilege_escalation", source: "user_role: super_admin" },

  // === Multi-field attacks ===
  { body: { amount: -1, isAdmin: true }, expect: true, source: "combined price + privilege attack" },
  { body: { amount: 0, discount: 100, role: "admin" }, expect: true, source: "triple attack: zero + discount + privilege" },
  { body: { price: -999, quantity: -10, discount: 200 }, expect: true, source: "full billing bypass attempt" },

  // === Legitimate requests (should pass) ===
  { body: { amount: 4900 }, expect: false, source: "valid amount" },
  { body: { price: 2999, quantity: 2 }, expect: false, source: "valid price + quantity" },
  { body: { role: "user" }, expect: false, source: "normal role" },
  { body: { role: "free" }, expect: false, source: "free tier role" },
  { body: { isAdmin: false }, expect: false, source: "isAdmin: false (non-admin)" },
  { body: { discount: 25 }, expect: false, source: "valid 25% discount" },
  { body: { discount: 0 }, expect: false, source: "zero discount (no coupon)" },
  { body: { plan: "pro" }, expect: false, source: "pro plan" },
  { body: { plan: "team" }, expect: false, source: "team plan" },
  { body: { quantity: 1 }, expect: false, source: "single item" },
  { body: { name: "John", email: "john@example.com" }, expect: false, source: "innocent fields" },
  { body: {}, expect: false, source: "empty body" },
]

describe("Benchmark: Business Logic Tamper", () => {
  for (const p of tamperPayloads) {
    it(`${p.expect ? "detects" : "passes"} — ${p.source}`, () => {
      const events: DetectionEvent[] = detectBusinessLogicTamper(p.body)
      if (p.expect) {
        expect(events.length, `Expected tamper in "${JSON.stringify(p.body)}"`).toBeGreaterThan(0)
        if (p.patternId) {
          expect(events.some((e) => e.patternId === p.patternId), `Expected patternId "${p.patternId}"`).toBe(true)
        }
      } else {
        expect(events.length, `Expected clean pass for "${JSON.stringify(p.body)}"`).toBe(0)
      }
    })
  }
})

describe("Benchmark: tamper summary", () => {
  it("has comprehensive payload coverage", () => {
    expect(tamperPayloads.length).toBeGreaterThanOrEqual(40)
  })

  it("covers all 6 detection categories", () => {
    const patternIds = new Set(
      tamperPayloads
        .filter((p) => p.expect && p.patternId)
        .map((p) => p.patternId),
    )
    expect(patternIds.has("tamper_negative_amount")).toBe(true)
    expect(patternIds.has("tamper_zero_amount")).toBe(true)
    expect(patternIds.has("tamper_negative_quantity")).toBe(true)
    expect(patternIds.has("tamper_full_discount")).toBe(true)
    expect(patternIds.has("tamper_negative_discount")).toBe(true)
    expect(patternIds.has("tamper_privilege_escalation")).toBe(true)
  })

  it("has legitimate false-positive tests", () => {
    const cleanPayloads = tamperPayloads.filter((p) => !p.expect)
    expect(cleanPayloads.length).toBeGreaterThanOrEqual(10)
  })
})
