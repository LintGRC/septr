package septr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

type NetHTTPMiddleware struct {
	config         *Config
	generalLimiter *SlidingWindowRateLimiter
	authLimiter    *SlidingWindowRateLimiter
	guard          *EngineGuard
	selfTestEvent  *sync.WaitGroup
	selfTestToken  string
	selfTestDone   bool
	selfTestMu     sync.Mutex
}

func NewNetHTTP(config *Config) *NetHTTPMiddleware {
	m := &NetHTTPMiddleware{config: config}
	if config.RateLimitEnabled() {
		rc := config.RateLimitConfig
		max, windowMs := 60, 60000
		if rc != nil {
			if rc.Max > 0 {
				max = rc.Max
			}
			if rc.WindowMs > 0 {
				windowMs = rc.WindowMs
			}
		}
		m.generalLimiter = NewSlidingWindowRateLimiter(max, windowMs)
		m.authLimiter = NewSlidingWindowRateLimiter(10, 60000)
	}
	if config.APIKey != "" && config.TelemetryEnabled() {
		pid := config.ProjectID
		if pid == "" {
			pid = config.APIKey
		}
		if config.framework == "" {
			config.framework = "nethttp"
		}
		initTelemetry(config, pid)
	}
	StartConfigPolling(config)
	m.selfTestToken = fmt.Sprintf("vs_st_%08x", rand.Int63())
	m.guard = NewEngineGuard(func(engine, reason string) {
		emitEvent(degradedEvent(engine, reason), config)
	})
	return m
}

func (m *NetHTTPMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Emergency kill switch: bypass everything, keep the app untouched.
		if killSwitchEngaged() {
			next.ServeHTTP(w, r)
			return
		}

		appEntered := false
		defer func() {
			if rec := recover(); rec != nil {
				if appEntered {
					panic(rec)
				}
				log.Printf("septr: recovered from middleware panic; failing open: %v", rec)
				appEntered = true
				next.ServeHTTP(w, r)
			}
		}()

		path := r.URL.Path
		method := r.Method
		headers := r.Header

		autoSelfTest(m.config, &m.selfTestDone, &m.selfTestMu)

		if path == selfTestPath && headers.Get("x-septr-self-test") == m.selfTestToken {
			if m.selfTestEvent != nil {
				m.selfTestEvent.Done()
			}
			testBody := map[string]interface{}{
				"api_key": "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
				"status":  "ok",
			}
			cleaned, stripDets := stripSensitiveData(testBody, m.config.StripFields)
			body, _ := json.Marshal(cleaned)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.Header().Set("X-Septr-Stripped", fmt.Sprintf("%d", len(stripDets)))
			w.WriteHeader(http.StatusOK)
			w.Write(body)
			return
		}

		ip := headers.Get("x-forwarded-for")
		if ip == "" {
			ip = r.RemoteAddr
		} else {
			ip = strings.Split(ip, ",")[0]
		}
		ip = strings.TrimSpace(ip)

		// --- Phase 1: Rate limit (no body needed) ---
		if m.config.RateLimitEnabled() && path != selfTestPath {
			limiter := m.generalLimiter
			if isAuthRoute(path) && (method == "POST" || method == "PUT" || method == "PATCH") {
				limiter = m.authLimiter
			}
			if limiter != nil {
				var allowed bool
				var resetMs int64
				GuardedVoid(m.guard, "rate_limit", func() {
					allowed, _, resetMs = limiter.Check(ip)
				})
				if !allowed {
					emitEvent(DetectionEvent{
						Type: "rate_limit", Severity: "medium",
						PatternID:   "rate_limit_exceeded",
						Description: "Rate limit exceeded for " + path,
						Route:       path, Method: method, Timestamp: nowMs(),
					}, m.config)
					w.Header().Set("Retry-After", fmt.Sprintf("%d", resetMs/1000))
					http.Error(w, `{"error":"Too many requests"}`, http.StatusTooManyRequests)
					return
				}
			}
		}

		// --- Phase 2: Read body once for request-phase engines ---
		var bodyBytes []byte
		var bodyMap map[string]interface{}
		needsBody := m.config.InputSanitizeEnabled() || m.config.TamperEnabled() || m.config.SSRFEnabled() || m.config.PromptInjectionEnabled()
		if needsBody && (method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE") {
			maxInspect := int64(m.config.RequestInspectMaxBytes())
			switch {
			case r.ContentLength > maxInspect:
				// Too large to inspect: leave the body untouched for the app.
			case r.ContentLength >= 0:
				bodyBytes, _ = io.ReadAll(r.Body)
				r.Body.Close()
				if len(bodyBytes) > 0 {
					json.Unmarshal(bodyBytes, &bodyMap)
				}
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			default:
				// Unknown length (chunked): inspect a prefix, stream the rest.
				prefix, _ := io.ReadAll(io.LimitReader(r.Body, maxInspect+1))
				if int64(len(prefix)) <= maxInspect {
					bodyBytes = prefix
				} else {
					bodyBytes = prefix[:maxInspect]
				}
				if len(bodyBytes) > 0 {
					json.Unmarshal(bodyBytes, &bodyMap)
				}
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
			}
		}

		// --- Phase 3: Tamper detection (business logic) ---
		if m.config.TamperEnabled() && bodyMap != nil {
			var tamperEvents []DetectionEvent
			GuardedVoid(m.guard, "tamper", func() {
				tamperEvents = detectBusinessLogicTamper(bodyMap, m.config.FieldConstraints, path, method)
			})
			for _, d := range tamperEvents {
				emitEvent(d, m.config)
			}
			if m.config.StrictMode && len(tamperEvents) > 0 {
				http.Error(w, `{"error":"Request blocked by Septr security filter"}`, http.StatusBadRequest)
				return
			}
		}

		// --- Phase 4: Input sanitize (SQLi / XSS) ---
		if m.config.InputSanitizeEnabled() {
			if bodyMap != nil {
				var sanitizeDets []DetectionEvent
				block := Guarded(m.guard, "input_sanitize", false, func() bool {
					b, dets := sanitizeInput(bodyMap, 0)
					sanitizeDets = dets
					return b
				})
				if block {
					for _, d := range sanitizeDets {
						emitEvent(d, m.config)
					}
					if m.config.StrictMode {
						http.Error(w, `{"error":"Request blocked by Septr security filter"}`, http.StatusBadRequest)
						return
					}
				}
			}

			queryMap := make(map[string]interface{})
			for k, vals := range r.URL.Query() {
				if len(vals) == 1 {
					queryMap[k] = vals[0]
				} else {
					queryMap[k] = vals
				}
			}
			if len(queryMap) > 0 {
				var qd []DetectionEvent
				block := Guarded(m.guard, "input_sanitize", false, func() bool {
					b, dets := sanitizeQuery(queryMap)
					qd = dets
					return b
				})
				if block {
					for _, d := range qd {
						emitEvent(d, m.config)
					}
					if m.config.StrictMode {
						http.Error(w, `{"error":"Request blocked by Septr security filter"}`, http.StatusBadRequest)
						return
					}
				}
			}
		}

		// --- Phase 5: SSRF detection ---
		if m.config.SSRFEnabled() {
			ssrfInput := path
			if len(r.URL.RawQuery) > 0 {
				ssrfInput += " " + r.URL.RawQuery
			}
			if len(bodyBytes) > 0 {
				ssrfInput += " " + string(bodyBytes)
			}
			var ssrfEvents []DetectionEvent
			GuardedVoid(m.guard, "ssrf", func() {
				ssrfEvents = detectSSRF(ssrfInput)
			})
			for _, d := range ssrfEvents {
				emitEvent(d, m.config)
			}
			if m.config.StrictMode && len(ssrfEvents) > 0 {
				http.Error(w, `{"error":"Request blocked by Septr security filter"}`, http.StatusForbidden)
				return
			}
		}

		// --- Phase 6: Prompt injection detection ---
		if m.config.PromptInjectionEnabled() {
			piInput := r.URL.RawQuery
			if len(bodyBytes) > 0 {
				piInput += " " + string(bodyBytes)
			}
			var piEvents []DetectionEvent
			GuardedVoid(m.guard, "prompt_injection", func() {
				piEvents = detectPromptInjection(piInput)
			})
			for _, d := range piEvents {
				emitEvent(d, m.config)
			}
			if m.config.StrictMode && len(piEvents) > 0 {
				http.Error(w, `{"error":"Request blocked by Septr security filter"}`, http.StatusForbidden)
				return
			}
		}

		// --- Phase 7: BOLA detection ---
		if m.config.BOLAEnabled() {
			auth := headers.Get("authorization")
			token := ""
			if strings.HasPrefix(auth, "Bearer ") {
				token = auth[7:]
			}
			var bolaEvent *DetectionEvent
			GuardedVoid(m.guard, "bola", func() {
				tokenClaims := extractTokenClaims(token)
				template := MatchRouteTemplate(path, m.config.RouteTemplates)
				routeParams := extractRouteParams(path)
				routeParamValues := map[string]string{}
				routeForEvent := path
				if template != "" {
					routeParams = extractRouteParams(template)
					routeParamValues = ExtractRouteParamValues(template, path)
					routeForEvent = template
				}
				bolaEvent = detectBOLA(routeParams, nil, tokenClaims, routeForEvent, method, routeParamValues)
			})
			if bolaEvent != nil {
				emitEvent(*bolaEvent, m.config)
				if m.config.StrictMode {
					w.WriteHeader(http.StatusNotFound)
					return
				}
			}
		}

		// --- Phase 8: Missing auth detection (advisory only) ---
		if m.config.MissingAuthEnabled() {
			authHeader := headers.Get("authorization")
			var maEvent *DetectionEvent
			GuardedVoid(m.guard, "missing_auth", func() {
				maEvent = detectMissingAuth(path, method, authHeader)
			})
			if maEvent != nil {
				emitEvent(*maEvent, m.config)
			}
		}

		// --- Phase 9: Secrets / response interceptor ---
		needsResponseInspection := m.config.SecretsEnabled() || m.config.AIRateLimitEnabled() || m.config.TenantAware != nil
		if needsResponseInspection {
			lw := &lockedWriter{
				header:   w.Header(),
				buf:      &bytes.Buffer{},
				dst:      w,
				maxBytes: m.config.ResponseScanMaxBytes(),
			}
			next.ServeHTTP(lw, r)

			// Advisory: report responses missing standard security headers.
			if m.config.SecurityHeadersEnabled() {
				for _, d := range Guarded(m.guard, "security_headers", []DetectionEvent{}, func() []DetectionEvent {
					return DetectMissingSecurityHeaders(w.Header())
				}) {
					emitEvent(d, m.config)
				}
			}

			if !lw.overflow && lw.statusCode >= 200 && lw.statusCode < 300 && lw.buf.Len() > 0 && lw.buf.Len() <= m.config.ResponseScanMaxBytes() {
				ct := w.Header().Get("Content-Type")
				isJSON := strings.Contains(ct, "application/json")

				// AI Rate Limit detection (response body)
				if m.config.AIRateLimitEnabled() {
					bodyStr := lw.buf.String()
					if hasRateLimitHint(bodyStr) {
						for _, d := range Guarded(m.guard, "ai_rate_limit", []DetectionEvent{}, func() []DetectionEvent {
							return detectAIRateLimit(bodyStr, path, method)
						}) {
							emitEvent(d, m.config)
						}
					}
				}

				// Tenant-aware cross-tenant leak detection
				if m.config.TenantAware != nil && isJSON {
					auth := headers.Get("authorization")
					token := ""
					if strings.HasPrefix(auth, "Bearer ") {
						token = auth[7:]
					}
					var tenantID string
					GuardedVoid(m.guard, "tenant_aware", func() {
						claims := extractTokenClaims(token)
						tenantID = extractTenantFromJwt(claims, m.config.TenantAware.JWTClaim)
					})
					if tenantID != "" {
						var respBody interface{}
						if err := json.Unmarshal(lw.buf.Bytes(), &respBody); err == nil {
							tc := guardedTenantCheck(m.guard, tenantID, respBody, *m.config.TenantAware)
							blocked, leaks := tc.Blocked, tc.Leaks
							for _, leak := range leaks {
								emitEvent(DetectionEvent{
									Type: "cross_tenant_leak", Severity: "critical",
									PatternID:   "cross_tenant_mismatch",
									Description: "Cross-tenant data leak at " + leak.Path + " — value does not match tenant " + tenantID,
									Route:       path, Method: method, Timestamp: nowMs(),
								}, m.config)
							}
							if blocked {
								http.Error(w, `{"error":"Cross-tenant data leak blocked"}`, http.StatusForbidden)
								return
							}
						}
					}
				}

				// Secrets stripping
				if m.config.SecretsEnabled() && isJSON {
					var bodyData interface{}
					if err := json.Unmarshal(lw.buf.Bytes(), &bodyData); err == nil {
						stripped := guardedStrip(m.guard, bodyData, m.config.StripFields)
						cleaned, stripDets := stripped.Body, stripped.Dets
						if len(stripDets) > 0 {
							for _, d := range stripDets {
								emitEvent(d, m.config)
							}
							newBody, _ := json.Marshal(cleaned)
							w.Header().Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
							w.Header().Set("X-Septr-Stripped", fmt.Sprintf("%d", len(stripDets)))
							w.WriteHeader(lw.statusCode)
							w.Write(newBody)
							return
						}
					}
				}
			}

			if lw.overflow {
				return
			}
			w.WriteHeader(lw.statusCode)
			w.Write(lw.buf.Bytes())
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *NetHTTPMiddleware) SelfTest(port int) bool {
	results := runEngineSelfTest()
	pipelineWorks := true
	for _, r := range results {
		if !r.Passed {
			pipelineWorks = false
			break
		}
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	m.selfTestEvent = wg

	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, selfTestPath))
	if err != nil {
		m.selfTestEvent = nil
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	stripped := resp.Header.Get("X-Septr-Stripped")
	responseInPipeline := stripped != ""
	m.selfTestEvent = nil

	if pipelineWorks && responseInPipeline {
		sendTestResults(results, map[string]interface{}{"runtime": "net/http", "port": port, "auto": true})
		return true
	}
	return false
}

type lockedWriter struct {
	header      http.Header
	buf         *bytes.Buffer
	statusCode  int
	wroteHeader bool
	// dst/maxBytes/overflow enable capped capture: once a response exceeds
	// maxBytes it is streamed straight to dst instead of held in memory.
	dst      http.ResponseWriter
	maxBytes int
	overflow bool
}

func (w *lockedWriter) Header() http.Header { return w.header }

func (w *lockedWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = code
}

// overflowTo commits the status and streams the buffered bytes plus this
// chunk straight to the client.
func (w *lockedWriter) overflowTo(first []byte) (int, error) {
	w.overflow = true
	w.dst.WriteHeader(w.statusCode)
	if w.buf.Len() > 0 {
		if _, err := w.dst.Write(w.buf.Bytes()); err != nil {
			return 0, err
		}
		w.buf.Reset()
	}
	return w.dst.Write(first)
}

func (w *lockedWriter) Write(b []byte) (int, error) {
	// net/http defaults an unset status to 200 on first write — mirror that
	// so a handler that never calls WriteHeader doesn't leave statusCode 0.
	if !w.wroteHeader {
		w.wroteHeader = true
		w.statusCode = http.StatusOK
	}
	if w.overflow {
		return w.dst.Write(b)
	}
	if w.maxBytes > 0 && w.dst != nil && w.buf.Len()+len(b) > w.maxBytes {
		return w.overflowTo(b)
	}
	return w.buf.Write(b)
}
