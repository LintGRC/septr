package septr

import (
	"testing"
)

func TestExtractTenantFromJwt_Valid(t *testing.T) {
	claims := map[string]string{"org_id": "tenant-123"}
	result := extractTenantFromJwt(claims, "org_id")
	if result != "tenant-123" {
		t.Errorf("expected tenant-123, got %s", result)
	}
}

func TestExtractTenantFromJwt_NotPresent(t *testing.T) {
	claims := map[string]string{"sub": "user-1"}
	result := extractTenantFromJwt(claims, "org_id")
	if result != "" {
		t.Errorf("expected empty string, got %s", result)
	}
}

func TestExtractTenantFromJwt_NilClaims(t *testing.T) {
	result := extractTenantFromJwt(nil, "org_id")
	if result != "" {
		t.Errorf("expected empty string for nil claims, got %s", result)
	}
}

func TestDetectCrossTenantLeaks_Mismatch(t *testing.T) {
	body := map[string]interface{}{
		"org_id":  "other-org",
		"data":    map[string]interface{}{"org_id": "my-org"},
		"name":    "test",
	}
	leaks := detectCrossTenantLeaks("my-org", body, "org_id")
	if len(leaks) != 1 {
		t.Fatalf("expected 1 leak, got %d", len(leaks))
	}
	if leaks[0].Value != "other-org" {
		t.Errorf("expected other-org, got %v", leaks[0].Value)
	}
}

func TestDetectCrossTenantLeaks_AllMatch(t *testing.T) {
	body := map[string]interface{}{
		"org_id": "my-org",
		"data":   map[string]interface{}{"org_id": "my-org"},
	}
	leaks := detectCrossTenantLeaks("my-org", body, "org_id")
	if len(leaks) > 0 {
		t.Errorf("expected no leaks, got %d", len(leaks))
	}
}

func TestDetectCrossTenantLeaks_Array(t *testing.T) {
	body := []interface{}{
		map[string]interface{}{"org_id": "my-org"},
		map[string]interface{}{"org_id": "bad-org"},
	}
	leaks := detectCrossTenantLeaks("my-org", body, "org_id")
	if len(leaks) != 1 {
		t.Fatalf("expected 1 leak, got %d", len(leaks))
	}
	if leaks[0].Value != "bad-org" {
		t.Errorf("expected bad-org, got %v", leaks[0].Value)
	}
}

func TestDetectCrossTenantLeaks_TenantColDifferentKey(t *testing.T) {
	body := map[string]interface{}{
		"tenant_id": "wrong-tenant",
	}
	leaks := detectCrossTenantLeaks("my-tenant", body, "tenant_id")
	if len(leaks) != 1 {
		t.Fatalf("expected 1 leak, got %d", len(leaks))
	}
}

func TestCreateTenantCheckResponse_BlockOnMismatch(t *testing.T) {
	body := map[string]interface{}{"org_id": "bad-org"}
	config := TenantAwareConfig{TenantColumn: "org_id", JWTClaim: "org_id", BlockOnMismatch: true}
	blocked, leaks := createTenantCheckResponse("my-org", body, config)
	if !blocked {
		t.Error("expected blocked")
	}
	if len(leaks) != 1 {
		t.Errorf("expected 1 leak, got %d", len(leaks))
	}
}

func TestCreateTenantCheckResponse_NoBlock(t *testing.T) {
	body := map[string]interface{}{"org_id": "bad-org"}
	config := TenantAwareConfig{TenantColumn: "org_id", JWTClaim: "org_id", BlockOnMismatch: false}
	blocked, leaks := createTenantCheckResponse("my-org", body, config)
	if blocked {
		t.Error("expected not blocked")
	}
	if len(leaks) != 1 {
		t.Errorf("expected 1 leak, got %d", len(leaks))
	}
}

func TestDetectCrossTenantLeaks_NilBody(t *testing.T) {
	leaks := detectCrossTenantLeaks("my-org", nil, "org_id")
	if len(leaks) > 0 {
		t.Errorf("expected no leaks for nil body, got %d", len(leaks))
	}
}

func TestToNumber_Float(t *testing.T) {
	n, ok := toNumber(3.14)
	if !ok || n != 3.14 {
		t.Errorf("expected 3.14, got %f", n)
	}
}

func TestToNumber_Int(t *testing.T) {
	n, ok := toNumber(42)
	if !ok || n != 42 {
		t.Errorf("expected 42, got %f", n)
	}
}

func TestToNumber_String(t *testing.T) {
	n, ok := toNumber("42")
	if !ok || n != 42 {
		t.Errorf("expected 42, got %f", n)
	}
}

func TestToNumber_StringNegative(t *testing.T) {
	n, ok := toNumber("-100")
	if !ok || n != -100 {
		t.Errorf("expected -100, got %f", n)
	}
}

func TestToNumber_InvalidString(t *testing.T) {
	_, ok := toNumber("not-a-number")
	if ok {
		t.Error("expected false for invalid string")
	}
}

func TestToNumber_Bool(t *testing.T) {
	_, ok := toNumber(true)
	if ok {
		t.Error("expected false for bool")
	}
}
