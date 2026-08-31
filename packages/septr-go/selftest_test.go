package septr

import (
	"sync"
	"testing"
)

func TestRunEngineSelfTest_AllEngines(t *testing.T) {
	results := runEngineSelfTest()
	if len(results) != 8 {
		t.Fatalf("expected 8 engine results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Passed {
			t.Errorf("engine %s should pass its self-test payload", r.Engine)
		}
	}
}

func TestAutoSelfTest_RunsOnce(t *testing.T) {
	config := &Config{APIKey: "vs_live_test", Telemetry: boolPtr(true), SelfTest: boolPtr(true)}
	var done bool
	var mu sync.Mutex
	autoSelfTest(config, &done, &mu)
	autoSelfTest(config, &done, &mu)
	// No panic and runs without error; done should be true (second call is a no-op)
	if !done {
		t.Fatal("expected selfTestDone to be true after first call")
	}
}

func TestAutoSelfTest_Disabled(t *testing.T) {
	config := &Config{SelfTest: boolPtr(false)}
	var done bool
	var mu sync.Mutex
	autoSelfTest(config, &done, &mu)
	if done {
		t.Fatal("expected selfTestDone to remain false when selfTest is disabled")
	}
}

func boolPtr(b bool) *bool { return &b }
