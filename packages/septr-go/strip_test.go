package septr

import "testing"

func TestStripSensitiveData_RedactsPassword(t *testing.T) {
	data := map[string]interface{}{"name": "John", "password": "secret123"}
	cleaned, dets := stripSensitiveData(data)
	m := cleaned.(map[string]interface{})
	if m["password"] != "[REDACTED]" || m["name"] != "John" {
		t.Fatal("expected password redacted")
	}
	if len(dets) == 0 {
		t.Fatal("expected detections")
	}
}

func TestStripSensitiveData_Nested(t *testing.T) {
	data := map[string]interface{}{
		"user": map[string]interface{}{"name": "John", "apiKey": "sk_live_" + "test"},
	}
	cleaned, _ := stripSensitiveData(data)
	m := cleaned.(map[string]interface{})
	u := m["user"].(map[string]interface{})
	if u["apiKey"] != "[REDACTED]" {
		t.Fatal("expected apiKey redacted")
	}
}

func TestStripSensitiveData_Lists(t *testing.T) {
	data := []interface{}{
		map[string]interface{}{"name": "John", "password": "abc"},
		map[string]interface{}{"name": "Jane", "password": "xyz"},
	}
	cleaned, _ := stripSensitiveData(data)
	l := cleaned.([]interface{})
	if l[0].(map[string]interface{})["password"] != "[REDACTED]" {
		t.Fatal("expected password redacted")
	}
}

func TestStripSensitiveData_EmbeddedSecrets(t *testing.T) {
	data := map[string]interface{}{"msg": "my key is sk_live_" + "abcdefghijklmnopqrstuvwxyz123456"}
	cleaned, dets := stripSensitiveData(data)
	if cleaned.(map[string]interface{})["msg"] != "[REDACTED]" {
		t.Fatal("expected secret redacted")
	}
	if len(dets) == 0 {
		t.Fatal("expected detections")
	}
}

func TestStripSensitiveData_MixedAdvisoryAndRealSecret(t *testing.T) {
	data := map[string]interface{}{"msg": "AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI sk_live_" + "abcdefghijklmnopqrstuvwxyz123456"}
	cleaned, _ := stripSensitiveData(data)
	if cleaned.(map[string]interface{})["msg"] != "[REDACTED]" {
		t.Fatal("real secret must still be redacted when an advisory-only key is present")
	}
}

func TestStripSensitiveData_AdvisoryOnlyNotRedacted(t *testing.T) {
	data := map[string]interface{}{"msg": "AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI"}
	cleaned, _ := stripSensitiveData(data)
	if cleaned.(map[string]interface{})["msg"] != "AIzaSy" + "BQom12tzI-rybN7Sf-KfeL4nwm-Rf7PmI" {
		t.Fatal("advisory-only key must not be redacted")
	}
}

func TestStripSensitiveData_SafeData(t *testing.T) {
	data := map[string]interface{}{"name": "John", "age": 30}
	cleaned, dets := stripSensitiveData(data)
	if len(dets) != 0 {
		t.Fatal("expected no detections")
	}
	m := cleaned.(map[string]interface{})
	if m["name"] != "John" {
		t.Fatal("expected unchanged")
	}
}

func TestStripSensitiveData_Nil(t *testing.T) {
	cleaned, _ := stripSensitiveData(nil)
	if cleaned != nil {
		t.Fatal("expected nil")
	}
}

func TestStripSensitiveData_CustomFields(t *testing.T) {
	data := map[string]interface{}{"internal_key": "secret-value"}
	cleaned, _ := stripSensitiveData(data, []string{"internal_key"})
	if cleaned.(map[string]interface{})["internal_key"] != "[REDACTED]" {
		t.Fatal("expected redacted")
	}
}
