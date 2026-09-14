package septr

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultEngineFailureThreshold = 3
	defaultEngineBudget           = 50 * time.Millisecond
)

// killSwitchEngaged reports whether the operator pulled the emergency bypass
// (SEPTR_DISABLED=true) so the middleware passes every request through while
// staying installed.
func killSwitchEngaged() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SEPTR_DISABLED"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// EngineGuard is the fail-open wrapper for detection engines: it catches
// panics, enforces a per-call time budget, and trips a per-engine circuit
// breaker after repeated failures so a broken engine is skipped for the rest
// of the process instead of failing (or slowing) every request.
type EngineGuard struct {
	mu         sync.Mutex
	failures   map[string]int
	open       map[string]bool
	reported   map[string]bool
	threshold  int
	budget     time.Duration
	onDegraded func(engine, reason string)
}

func NewEngineGuard(onDegraded func(engine, reason string)) *EngineGuard {
	return &EngineGuard{
		failures:   map[string]int{},
		open:       map[string]bool{},
		reported:   map[string]bool{},
		threshold:  defaultEngineFailureThreshold,
		budget:     defaultEngineBudget,
		onDegraded: onDegraded,
	}
}

func (g *EngineGuard) IsOpen(engine string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open[engine]
}

// Guarded runs fn under the guard. Engines that are open, panic, or exceed
// the time budget return def.
func Guarded[T any](g *EngineGuard, engine string, def T, fn func() T) T {
	if g == nil {
		return fn()
	}
	g.mu.Lock()
	open := g.open[engine]
	g.mu.Unlock()
	if open {
		return def
	}

	var result T
	ok := true
	start := time.Now()
	func() {
		defer func() {
			if r := recover(); r != nil {
				ok = false
				g.recordFailure(engine, fmt.Sprintf("panic: %v", r))
			}
		}()
		result = fn()
	}()
	if !ok {
		return def
	}
	if g.budget > 0 {
		if elapsed := time.Since(start); elapsed > g.budget {
			g.recordFailure(engine, fmt.Sprintf("took %s (budget %s)", elapsed.Round(time.Millisecond), g.budget))
		}
	}
	return result
}

// GuardedVoid is Guarded for engines that only produce side effects (results
// captured by the closure).
func GuardedVoid(g *EngineGuard, engine string, fn func()) {
	Guarded(g, engine, struct{}{}, func() struct{} {
		fn()
		return struct{}{}
	})
}

// StripResult carries a (possibly redacted) body plus the detections that
// justify the rewrite.
type StripResult struct {
	Body interface{}
	Dets []DetectionEvent
}

// guardedStrip runs secret-stripping under the engine guard.
func guardedStrip(g *EngineGuard, data interface{}, fields []string) StripResult {
	return Guarded(g, "secrets", StripResult{Body: data}, func() StripResult {
		cleaned, dets := stripSensitiveData(data, fields)
		return StripResult{Body: cleaned, Dets: dets}
	})
}

// TenantCheckResult carries the tenant-leak outcome.
type TenantCheckResult struct {
	Blocked bool
	Leaks   []TenantLeak
}

// guardedTenantCheck runs cross-tenant leak detection under the engine guard.
func guardedTenantCheck(g *EngineGuard, tenantID string, body interface{}, cfg TenantAwareConfig) TenantCheckResult {
	return Guarded(g, "tenant_aware", TenantCheckResult{}, func() TenantCheckResult {
		blocked, leaks := createTenantCheckResponse(tenantID, body, cfg)
		return TenantCheckResult{Blocked: blocked, Leaks: leaks}
	})
}

func (g *EngineGuard) recordFailure(engine, reason string) {
	g.mu.Lock()
	if g.open[engine] {
		g.mu.Unlock()
		return
	}
	g.failures[engine]++
	report := false
	if g.failures[engine] >= g.threshold {
		g.open[engine] = true
		if !g.reported[engine] {
			g.reported[engine] = true
			report = true
		}
	}
	g.mu.Unlock()

	log.Printf("septr: engine %q failed (%s)", engine, reason)
	if report && g.onDegraded != nil {
		g.onDegraded(engine, reason)
	}
}

// degradedEvent is the single system event emitted when an engine trips its
// breaker — operators see it in the dashboard instead of silently losing a
// detection class.
func degradedEvent(engine, reason string) DetectionEvent {
	return DetectionEvent{
		Type:      "system",
		Severity:  "info",
		PatternID: "engine_degraded",
		Description: fmt.Sprintf(
			"Engine `%s` degraded and was disabled for this process (%s). Restart the app to retry, or upgrade the Septr SDK.",
			engine, reason,
		),
		Timestamp: nowMs(),
	}
}
