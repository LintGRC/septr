package septr

import (
	"strings"
)

var pricingFields = []string{
	"amount", "price", "total", "cost", "value",
	"subtotal", "grand_total", "order_total", "payment_amount",
}

var quantityFields = []string{
	"quantity", "qty", "count", "units", "items",
}

var permissionFields = []string{
	"role", "admin", "isAdmin", "is_admin", "superadmin",
	"super_admin", "permissions", "privilege", "access_level",
	"user_role", "account_type", "plan", "tier",
}

var discountFields = []string{
	"discount", "discount_percent", "discount_amount",
	"coupon", "promo", "promo_code", "voucher",
}

var privilegedValues = map[string]bool{
	"admin": true, "superadmin": true, "super_admin": true,
	"owner": true, "root": true, "god": true,
	"sysadmin": true, "moderator": true, "mod": true, "staff": true,
}

var booleanPrivilegeFields = map[string]bool{
	"admin": true, "isAdmin": true, "is_admin": true,
	"superadmin": true, "super_admin": true,
	"isSuperAdmin": true, "is_super_admin": true,
	"isOwner": true, "is_owner": true,
	"staff": true, "isStaff": true, "is_staff": true,
	"moderator": true, "isModerator": true,
}

func detectSuspiciousPricing(body map[string]interface{}, route, method string) []DetectionEvent {
	var events []DetectionEvent
	t := nowMs()

	for _, field := range pricingFields {
		val, ok := body[field]
		if !ok {
			continue
		}
		num, isNum := toNumber(val)
		if !isNum {
			continue
		}
		if num < 0 {
			events = append(events, DetectionEvent{
				Type: "business_logic_tamper", Severity: "critical",
				PatternID: "tamper_negative_amount",
				Description: "Pricing field `" + field + "` has negative value — the server should reject negative amounts",
				Route: route, Method: method, Timestamp: t,
			})
		} else if num == 0 {
			events = append(events, DetectionEvent{
				Type: "business_logic_tamper", Severity: "high",
				PatternID: "tamper_zero_amount",
				Description: "Pricing field `" + field + "` is zero — verify this is intentional and not client-side price manipulation",
				Route: route, Method: method, Timestamp: t,
			})
		}
	}

	for _, field := range quantityFields {
		val, ok := body[field]
		if !ok {
			continue
		}
		num, isNum := toNumber(val)
		if !isNum {
			continue
		}
		if num < 0 {
			events = append(events, DetectionEvent{
				Type: "business_logic_tamper", Severity: "critical",
				PatternID: "tamper_negative_quantity",
				Description: "Quantity field `" + field + "` has negative value",
				Route: route, Method: method, Timestamp: t,
			})
		}
	}

	for _, field := range discountFields {
		val, ok := body[field]
		if !ok {
			continue
		}
		num, isNum := toNumber(val)
		if !isNum {
			continue
		}
		if num >= 100 {
			events = append(events, DetectionEvent{
				Type: "business_logic_tamper", Severity: "critical",
				PatternID: "tamper_full_discount",
				Description: "Discount field `" + field + "` is >=100% — a 100%+ discount means free product",
				Route: route, Method: method, Timestamp: t,
			})
		} else if num < 0 {
			events = append(events, DetectionEvent{
				Type: "business_logic_tamper", Severity: "high",
				PatternID: "tamper_negative_discount",
				Description: "Discount field `" + field + "` has negative value",
				Route: route, Method: method, Timestamp: t,
			})
		}
	}

	return events
}

func detectSuspiciousPermissions(body map[string]interface{}, route, method string) []DetectionEvent {
	var events []DetectionEvent
	t := nowMs()

	for _, field := range permissionFields {
		val, ok := body[field]
		if !ok {
			continue
		}

		switch v := val.(type) {
		case bool:
			if booleanPrivilegeFields[field] && v {
				events = append(events, DetectionEvent{
					Type: "business_logic_tamper", Severity: "critical",
					PatternID: "tamper_privilege_escalation",
					Description: "Boolean privilege field `" + field + "` set to true in request body — permissions must be set server-side",
					Route: route, Method: method, Timestamp: t,
				})
			}
		case string:
			if privilegedValues[strings.ToLower(v)] {
				events = append(events, DetectionEvent{
					Type: "business_logic_tamper", Severity: "critical",
					PatternID: "tamper_privilege_escalation",
					Description: "Permission field `" + field + "` set to privileged value `" + v + "` in request body",
					Route: route, Method: method, Timestamp: t,
				})
			}
		}
	}

	return events
}

func validateConstraints(body map[string]interface{}, constraints []FieldConstraint, route, method string) []DetectionEvent {
	var events []DetectionEvent
	t := nowMs()

	for _, c := range constraints {
		val, exists := body[c.Field]

		switch c.Constraint.Type {
		case "readonly":
			if exists {
				events = append(events, DetectionEvent{
					Type: "business_logic_tamper", Severity: "critical",
					PatternID: "tamper_readonly_field",
					Description: "Read-only field `" + c.Field + "` was included in request body — remove it from client input",
					Route: route, Method: method, Timestamp: t,
				})
			}

		case "range":
			if !exists {
				continue
			}
			num, isNum := toNumber(val)
			if !isNum {
				events = append(events, DetectionEvent{
					Type: "business_logic_tamper", Severity: "high",
					PatternID: "tamper_invalid_type",
					Description: "Field `" + c.Field + "` expected a number but got non-numeric value",
					Route: route, Method: method, Timestamp: t,
				})
				continue
			}
			if c.Constraint.Min != nil && num < *c.Constraint.Min {
				events = append(events, DetectionEvent{
					Type: "business_logic_tamper", Severity: "high",
					PatternID: "tamper_below_min",
					Description: "Field `" + c.Field + "` value is below minimum",
					Route: route, Method: method, Timestamp: t,
				})
			}
			if c.Constraint.Max != nil && num > *c.Constraint.Max {
				events = append(events, DetectionEvent{
					Type: "business_logic_tamper", Severity: "high",
					PatternID: "tamper_above_max",
					Description: "Field `" + c.Field + "` value is above maximum",
					Route: route, Method: method, Timestamp: t,
				})
			}

		case "enum":
			if !exists {
				continue
			}
			found := false
			for _, allowed := range c.Constraint.Values {
				if val == allowed {
					found = true
					break
				}
			}
			if !found {
				events = append(events, DetectionEvent{
					Type: "business_logic_tamper", Severity: "high",
					PatternID: "tamper_invalid_enum",
					Description: "Field `" + c.Field + "` value is not in allowed values",
					Route: route, Method: method, Timestamp: t,
				})
			}
		}
	}

	return events
}

func detectBusinessLogicTamper(body map[string]interface{}, constraints []FieldConstraint, route, method string) []DetectionEvent {
	if body == nil {
		return nil
	}

	var events []DetectionEvent

	events = append(events, detectSuspiciousPricing(body, route, method)...)
	events = append(events, detectSuspiciousPermissions(body, route, method)...)

	if len(constraints) > 0 {
		events = append(events, validateConstraints(body, constraints, route, method)...)
	}

	return events
}
