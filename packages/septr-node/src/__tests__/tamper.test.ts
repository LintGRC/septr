import { describe, it, expect } from "vitest"
import { detectBusinessLogicTamper } from "../core/tamper"

describe("detectBusinessLogicTamper", () => {
  describe("auto-detection: pricing fields", () => {
    it("detects negative amount", () => {
      const events = detectBusinessLogicTamper({ amount: -100 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
      expect(events[0].severity).toBe("critical")
    })

    it("detects negative price", () => {
      const events = detectBusinessLogicTamper({ price: -50 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
    })

    it("detects negative total", () => {
      const events = detectBusinessLogicTamper({ total: -999 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
    })

    it("detects negative cost", () => {
      const events = detectBusinessLogicTamper({ cost: -1 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
    })

    it("detects zero amount", () => {
      const events = detectBusinessLogicTamper({ amount: 0 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_zero_amount")
      expect(events[0].severity).toBe("high")
    })

    it("detects zero price", () => {
      const events = detectBusinessLogicTamper({ price: 0 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_zero_amount")
    })

    it("accepts valid positive amount", () => {
      const events = detectBusinessLogicTamper({ amount: 4900 })
      expect(events.length).toBe(0)
    })

    it("accepts valid positive price", () => {
      const events = detectBusinessLogicTamper({ price: 2999 })
      expect(events.length).toBe(0)
    })

    it("handles string amounts", () => {
      const events = detectBusinessLogicTamper({ amount: "-100" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
    })

    it("handles string zero", () => {
      const events = detectBusinessLogicTamper({ amount: "0" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_zero_amount")
    })

    it("accepts non-numeric strings", () => {
      const events = detectBusinessLogicTamper({ amount: "free" })
      expect(events.length).toBe(0)
    })

    it("detects negative subtotal", () => {
      const events = detectBusinessLogicTamper({ subtotal: -50 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
    })

    it("detects negative grand_total", () => {
      const events = detectBusinessLogicTamper({ grand_total: -100 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
    })

    it("detects negative payment_amount", () => {
      const events = detectBusinessLogicTamper({ payment_amount: -25 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_amount")
    })
  })

  describe("auto-detection: quantity fields", () => {
    it("detects negative quantity", () => {
      const events = detectBusinessLogicTamper({ quantity: -5 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_quantity")
      expect(events[0].severity).toBe("critical")
    })

    it("detects negative qty", () => {
      const events = detectBusinessLogicTamper({ qty: -1 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_quantity")
    })

    it("accepts valid quantity", () => {
      const events = detectBusinessLogicTamper({ quantity: 3 })
      expect(events.length).toBe(0)
    })

    it("accepts zero quantity", () => {
      const events = detectBusinessLogicTamper({ quantity: 0 })
      expect(events.length).toBe(0)
    })
  })

  describe("auto-detection: discount fields", () => {
    it("detects 100% discount", () => {
      const events = detectBusinessLogicTamper({ discount: 100 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_full_discount")
      expect(events[0].severity).toBe("critical")
    })

    it("detects >100% discount", () => {
      const events = detectBusinessLogicTamper({ discount_percent: 200 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_full_discount")
    })

    it("detects negative discount", () => {
      const events = detectBusinessLogicTamper({ discount: -50 })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_negative_discount")
      expect(events[0].severity).toBe("high")
    })

    it("accepts valid discount", () => {
      const events = detectBusinessLogicTamper({ discount_percent: 25 })
      expect(events.length).toBe(0)
    })
  })

  describe("auto-detection: permission fields", () => {
    it("detects admin: true", () => {
      const events = detectBusinessLogicTamper({ isAdmin: true })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
      expect(events[0].severity).toBe("critical")
    })

    it("detects is_admin: true", () => {
      const events = detectBusinessLogicTamper({ is_admin: true })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("detects superadmin: true", () => {
      const events = detectBusinessLogicTamper({ superadmin: true })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("detects role: admin", () => {
      const events = detectBusinessLogicTamper({ role: "admin" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("detects role: superadmin", () => {
      const events = detectBusinessLogicTamper({ role: "superadmin" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("detects role: owner", () => {
      const events = detectBusinessLogicTamper({ role: "owner" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("detects role: root", () => {
      const events = detectBusinessLogicTamper({ role: "root" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("detects role: moderator", () => {
      const events = detectBusinessLogicTamper({ role: "moderator" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("detects role: staff", () => {
      const events = detectBusinessLogicTamper({ role: "staff" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("accepts role: user", () => {
      const events = detectBusinessLogicTamper({ role: "user" })
      expect(events.length).toBe(0)
    })

    it("accepts role: free", () => {
      const events = detectBusinessLogicTamper({ role: "free" })
      expect(events.length).toBe(0)
    })

    it("accepts isAdmin: false", () => {
      const events = detectBusinessLogicTamper({ isAdmin: false })
      expect(events.length).toBe(0)
    })

    it("detects plan: admin", () => {
      const events = detectBusinessLogicTamper({ plan: "admin" })
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_privilege_escalation")
    })

    it("accepts plan: pro", () => {
      const events = detectBusinessLogicTamper({ plan: "pro" })
      expect(events.length).toBe(0)
    })
  })

  describe("constraint validation: readonly", () => {
    it("detects readonly field in body", () => {
      const events = detectBusinessLogicTamper(
        { createdAt: "2024-01-01" },
        [{ field: "createdAt", constraint: { type: "readonly" } }],
      )
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_readonly_field")
      expect(events[0].severity).toBe("critical")
    })

    it("allows missing readonly field", () => {
      const events = detectBusinessLogicTamper(
        { name: "test" },
        [{ field: "createdAt", constraint: { type: "readonly" } }],
      )
      expect(events.length).toBe(0)
    })
  })

  describe("constraint validation: range", () => {
    it("detects value below min", () => {
      const events = detectBusinessLogicTamper(
        { amount: 50 },
        [{ field: "amount", constraint: { type: "range", min: 100 } }],
      )
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_below_min")
    })

    it("detects value above max", () => {
      const events = detectBusinessLogicTamper(
        { quantity: 1000 },
        [{ field: "quantity", constraint: { type: "range", max: 100 } }],
      )
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_above_max")
    })

    it("accepts value within range", () => {
      const events = detectBusinessLogicTamper(
        { amount: 500 },
        [{ field: "amount", constraint: { type: "range", min: 100, max: 1000 } }],
      )
      expect(events.length).toBe(0)
    })

    it("detects non-number in range field", () => {
      const events = detectBusinessLogicTamper(
        { amount: "free" },
        [{ field: "amount", constraint: { type: "range", min: 100 } }],
      )
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_invalid_type")
    })

    it("accepts undefined field (not present)", () => {
      const events = detectBusinessLogicTamper(
        { name: "test" },
        [{ field: "amount", constraint: { type: "range", min: 100 } }],
      )
      expect(events.length).toBe(0)
    })
  })

  describe("constraint validation: enum", () => {
    it("detects invalid enum value", () => {
      const events = detectBusinessLogicTamper(
        { plan: "enterprise" },
        [{ field: "plan", constraint: { type: "enum", values: ["free", "pro", "team"] } }],
      )
      expect(events.length).toBe(1)
      expect(events[0].patternId).toBe("tamper_invalid_enum")
    })

    it("accepts valid enum value", () => {
      const events = detectBusinessLogicTamper(
        { plan: "pro" },
        [{ field: "plan", constraint: { type: "enum", values: ["free", "pro", "team"] } }],
      )
      expect(events.length).toBe(0)
    })

    it("accepts undefined enum field", () => {
      const events = detectBusinessLogicTamper(
        { name: "test" },
        [{ field: "plan", constraint: { type: "enum", values: ["free", "pro"] } }],
      )
      expect(events.length).toBe(0)
    })
  })

  describe("combined detections", () => {
    it("detects multiple issues at once", () => {
      const events = detectBusinessLogicTamper({
        amount: -100,
        isAdmin: true,
        discount: 100,
        quantity: -5,
      })
      expect(events.length).toBe(4)
      const patternIds = events.map((e) => e.patternId)
      expect(patternIds).toContain("tamper_negative_amount")
      expect(patternIds).toContain("tamper_privilege_escalation")
      expect(patternIds).toContain("tamper_full_discount")
      expect(patternIds).toContain("tamper_negative_quantity")
    })

    it("combines auto-detection with constraints", () => {
      const events = detectBusinessLogicTamper(
        { amount: -100, role: "admin" },
        [{ field: "amount", constraint: { type: "range", min: 100 } }],
      )
      expect(events.length).toBeGreaterThanOrEqual(2)
      const patternIds = events.map((e) => e.patternId)
      expect(patternIds).toContain("tamper_negative_amount")
      expect(patternIds).toContain("tamper_privilege_escalation")
    })
  })

  describe("edge cases", () => {
    it("returns empty for null body", () => {
      expect(detectBusinessLogicTamper(null as any)).toEqual([])
    })

    it("returns empty for undefined body", () => {
      expect(detectBusinessLogicTamper(undefined as any)).toEqual([])
    })

    it("returns empty for non-object body", () => {
      expect(detectBusinessLogicTamper("string" as any)).toEqual([])
    })

    it("returns empty for empty body", () => {
      expect(detectBusinessLogicTamper({})).toEqual([])
    })

    it("includes route and method in events", () => {
      const events = detectBusinessLogicTamper(
        { amount: -100 },
        undefined,
        "/api/checkout",
        "POST",
      )
      expect(events[0].route).toBe("/api/checkout")
      expect(events[0].method).toBe("POST")
    })

    it("sets type to business_logic_tamper", () => {
      const events = detectBusinessLogicTamper({ amount: -100 })
      expect(events[0].type).toBe("business_logic_tamper")
    })
  })
})
