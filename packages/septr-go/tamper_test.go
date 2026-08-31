package septr

import (
	"testing"
)

func TestDetectBusinessLogicTamper_NegativeAmount(t *testing.T) {
	body := map[string]interface{}{"amount": -100}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for negative amount")
	}
	if events[0].PatternID != "tamper_negative_amount" {
		t.Errorf("expected tamper_negative_amount, got %s", events[0].PatternID)
	}
	if events[0].Severity != "critical" {
		t.Errorf("expected severity critical, got %s", events[0].Severity)
	}
}

func TestDetectBusinessLogicTamper_ZeroAmount(t *testing.T) {
	body := map[string]interface{}{"price": 0}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for zero amount")
	}
	if events[0].PatternID != "tamper_zero_amount" {
		t.Errorf("expected tamper_zero_amount, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_NegativeQuantity(t *testing.T) {
	body := map[string]interface{}{"quantity": -5}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for negative quantity")
	}
	if events[0].PatternID != "tamper_negative_quantity" {
		t.Errorf("expected tamper_negative_quantity, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_FullDiscount(t *testing.T) {
	body := map[string]interface{}{"discount": 100}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for 100% discount")
	}
	if events[0].PatternID != "tamper_full_discount" {
		t.Errorf("expected tamper_full_discount, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_NegativeDiscount(t *testing.T) {
	body := map[string]interface{}{"coupon": -1}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for negative discount")
	}
	if events[0].PatternID != "tamper_negative_discount" {
		t.Errorf("expected tamper_negative_discount, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_PrivilegeEscalation_Bool(t *testing.T) {
	body := map[string]interface{}{"isAdmin": true}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for privilege escalation via boolean")
	}
	if events[0].PatternID != "tamper_privilege_escalation" {
		t.Errorf("expected tamper_privilege_escalation, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_PrivilegeEscalation_String(t *testing.T) {
	body := map[string]interface{}{"role": "admin"}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for privilege escalation via string")
	}
}

func TestDetectBusinessLogicTamper_ReadonlyConstraint(t *testing.T) {
	body := map[string]interface{}{"id": "123"}
	constraints := []FieldConstraint{
		{Field: "id", Constraint: FieldConstraintDef{Type: "readonly"}},
	}
	events := detectBusinessLogicTamper(body, constraints, "", "")
	if len(events) == 0 {
		t.Fatal("expected readonly constraint violation")
	}
	if events[0].PatternID != "tamper_readonly_field" {
		t.Errorf("expected tamper_readonly_field, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_RangeConstraint(t *testing.T) {
	minVal := float64(0)
	maxVal := float64(100)
	body := map[string]interface{}{"age": -1}
	constraints := []FieldConstraint{
		{Field: "age", Constraint: FieldConstraintDef{Type: "range", Min: &minVal, Max: &maxVal}},
	}
	events := detectBusinessLogicTamper(body, constraints, "", "")
	if len(events) == 0 {
		t.Fatal("expected range constraint violation (below min)")
	}
	if events[0].PatternID != "tamper_below_min" {
		t.Errorf("expected tamper_below_min, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_EnumConstraint(t *testing.T) {
	body := map[string]interface{}{"status": "hacked"}
	constraints := []FieldConstraint{
		{Field: "status", Constraint: FieldConstraintDef{Type: "enum", Values: []interface{}{"active", "inactive"}}},
	}
	events := detectBusinessLogicTamper(body, constraints, "", "")
	if len(events) == 0 {
		t.Fatal("expected enum constraint violation")
	}
	if events[0].PatternID != "tamper_invalid_enum" {
		t.Errorf("expected tamper_invalid_enum, got %s", events[0].PatternID)
	}
}

func TestDetectBusinessLogicTamper_Safe(t *testing.T) {
	body := map[string]interface{}{
		"name":  "John",
		"email": "john@example.com",
	}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) > 0 {
		t.Errorf("expected no detection for safe body, got %d events", len(events))
	}
}

func TestDetectBusinessLogicTamper_NilBody(t *testing.T) {
	events := detectBusinessLogicTamper(nil, nil, "", "")
	if len(events) > 0 {
		t.Errorf("expected no events for nil body, got %d", len(events))
	}
}

func TestDetectBusinessLogicTamper_StringAmount(t *testing.T) {
	body := map[string]interface{}{"amount": "-50"}
	events := detectBusinessLogicTamper(body, nil, "", "")
	if len(events) == 0 {
		t.Fatal("expected detection for string negative amount")
	}
}
