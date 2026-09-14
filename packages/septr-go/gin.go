//go:build !nogin

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

	"github.com/gin-gonic/gin"
)

type GinMiddleware struct {
	config         *Config
	generalLimiter *SlidingWindowRateLimiter
	authLimiter    *SlidingWindowRateLimiter
	guard          *EngineGuard
	selfTestEvent  *sync.WaitGroup
	selfTestToken  string
	selfTestDone   bool
	selfTestMu     sync.Mutex
}

func NewGin(config *Config) *GinMiddleware {
	m := &GinMiddleware{config: config}
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
			config.framework = "gin"
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

func (m *GinMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Emergency kill switch: bypass everything, keep the app untouched.
		if killSwitchEngaged() {
			c.Next()
			return
		}

		appEntered := false
		defer func() {
			if r := recover(); r != nil {
				if appEntered {
					panic(r)
				}
				log.Printf("septr: recovered from middleware panic; failing open: %v", r)
				appEntered = true
				c.Next()
			}
		}()

		path := c.Request.URL.Path
		method := c.Request.Method
		headers := c.Request.Header

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
			c.Header("X-Septr-Stripped", fmt.Sprintf("%d", len(stripDets)))
			c.JSON(http.StatusOK, cleaned)
			c.Abort()
			return
		}

		event := m.runPipeline(c.Writer, c.Request, path, method, headers, c.FullPath())
		if event != nil {
			if event.statusCode == 429 {
				c.JSON(event.statusCode, gin.H{"error": "Too many requests"})
				c.Abort()
				return
			}
			if event.statusCode == 403 {
				c.JSON(event.statusCode, gin.H{"error": "Request blocked by Septr security filter"})
				c.Abort()
				return
			}
			if event.statusCode == 400 {
				c.JSON(event.statusCode, gin.H{"error": "Request blocked by Septr security filter"})
				c.Abort()
				return
			}
			if event.statusCode == 404 {
				c.AbortWithStatus(event.statusCode)
				return
			}
			return
		}

		needsResponseInspection := m.config.SecretsEnabled() || m.config.AIRateLimitEnabled() || m.config.TenantAware != nil
		if needsResponseInspection {
			iw := &ginInspectWriter{
				ResponseWriter: c.Writer,
				statusCode:     http.StatusOK,
				maxBytes:       m.config.ResponseScanMaxBytes(),
				guard:          m.guard,
			}
			c.Writer = iw
			appEntered = true
			c.Next()
			iw.finalize(m.config, path, method, headers)
			return
		}

		appEntered = true
		c.Next()
	}
}

type ginInspectWriter struct {
	gin.ResponseWriter
	buf         bytes.Buffer
	statusCode  int
	wroteHeader bool
	maxBytes    int
	overflow    bool
	guard       *EngineGuard
}

func (w *ginInspectWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = code
}

// overflowTo commits the status and streams the buffered bytes plus this
// chunk straight to the client — responses over the scan cap are never held
// in memory.
func (w *ginInspectWriter) overflowTo(first []byte) (int, error) {
	w.overflow = true
	w.ResponseWriter.WriteHeader(w.statusCode)
	if w.buf.Len() > 0 {
		if _, err := w.ResponseWriter.Write(w.buf.Bytes()); err != nil {
			return 0, err
		}
		w.buf.Reset()
	}
	return w.ResponseWriter.Write(first)
}

func (w *ginInspectWriter) write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.statusCode = http.StatusOK
	}
	if w.overflow {
		return w.ResponseWriter.Write(b)
	}
	if w.maxBytes > 0 && w.buf.Len()+len(b) > w.maxBytes {
		return w.overflowTo(b)
	}
	return w.buf.Write(b)
}

func (w *ginInspectWriter) Write(b []byte) (int, error) {
	return w.write(b)
}

func (w *ginInspectWriter) WriteString(s string) (int, error) {
	return w.write([]byte(s))
}

func (w *ginInspectWriter) WriteHeaderNow() {}

func (w *ginInspectWriter) Status() int { return w.statusCode }

func (w *ginInspectWriter) Size() int { return w.buf.Len() }

func (w *ginInspectWriter) finalize(config *Config, path, method string, headers http.Header) {
	if w.overflow {
		// Already streamed straight to the client.
		return
	}
	// Advisory: report responses missing standard security headers.
	if config.SecurityHeadersEnabled() {
		for _, d := range Guarded(w.guard, "security_headers", []DetectionEvent{}, func() []DetectionEvent {
			return DetectMissingSecurityHeaders(w.Header())
		}) {
			emitEvent(d, config)
		}
	}
	if w.statusCode >= 200 && w.statusCode < 300 && w.buf.Len() > 0 && w.buf.Len() <= config.ResponseScanMaxBytes() {
		ct := w.Header().Get("Content-Type")
		isJSON := strings.Contains(ct, "application/json")

		if config.AIRateLimitEnabled() {
			bodyStr := w.buf.String()
			if hasRateLimitHint(bodyStr) {
				for _, d := range Guarded(w.guard, "ai_rate_limit", []DetectionEvent{}, func() []DetectionEvent {
					return detectAIRateLimit(bodyStr, path, method)
				}) {
					emitEvent(d, config)
				}
			}
		}

		if config.TenantAware != nil && isJSON {
			auth := headers.Get("authorization")
			token := ""
			if strings.HasPrefix(auth, "Bearer ") {
				token = auth[7:]
			}
			var tenantID string
			GuardedVoid(w.guard, "tenant_aware", func() {
				claims := extractTokenClaims(token)
				tenantID = extractTenantFromJwt(claims, config.TenantAware.JWTClaim)
			})
			if tenantID != "" {
				var respBody interface{}
				if err := json.Unmarshal(w.buf.Bytes(), &respBody); err == nil {
					tc := guardedTenantCheck(w.guard, tenantID, respBody, *config.TenantAware)
					blocked, leaks := tc.Blocked, tc.Leaks
					for _, leak := range leaks {
						emitEvent(DetectionEvent{
							Type: "cross_tenant_leak", Severity: "critical",
							PatternID:   "cross_tenant_mismatch",
							Description: "Cross-tenant data leak at " + leak.Path + " — value does not match tenant " + tenantID,
							Route:       path, Method: method, Timestamp: nowMs(),
						}, config)
					}
					if blocked {
						body := `{"error":"Cross-tenant data leak blocked"}`
						w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
						w.ResponseWriter.WriteHeader(http.StatusForbidden)
						w.ResponseWriter.Write([]byte(body))
						return
					}
				}
			}
		}

		if config.SecretsEnabled() && isJSON {
			var bodyData interface{}
			if err := json.Unmarshal(w.buf.Bytes(), &bodyData); err == nil {
				stripped := guardedStrip(w.guard, bodyData, config.StripFields)
				cleaned, stripDets := stripped.Body, stripped.Dets
				if len(stripDets) > 0 {
					for _, d := range stripDets {
						emitEvent(d, config)
					}
					newBody, _ := json.Marshal(cleaned)
					w.Header().Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
					w.Header().Set("X-Septr-Stripped", fmt.Sprintf("%d", len(stripDets)))
					w.ResponseWriter.WriteHeader(w.statusCode)
					w.ResponseWriter.Write(newBody)
					return
				}
			}
		}
	}

	w.ResponseWriter.WriteHeader(w.statusCode)
	w.ResponseWriter.Write(w.buf.Bytes())
}

type pipelineEvent struct {
	statusCode int
}

func (m *GinMiddleware) runPipeline(w http.ResponseWriter, r *http.Request, path, method string, headers http.Header, routeTemplate string) *pipelineEvent {
	ip := headers.Get("x-forwarded-for")
	if ip == "" {
		ip = r.RemoteAddr
	} else {
		ip = strings.Split(ip, ",")[0]
	}
	ip = strings.TrimSpace(ip)

	// Phase 1: Rate limit
	if m.config.RateLimitEnabled() && path != selfTestPath {
		limiter := m.generalLimiter
		if isAuthRoute(path) && (method == "POST" || method == "PUT" || method == "PATCH") {
			limiter = m.authLimiter
		}
		if limiter != nil {
			allowed := Guarded(m.guard, "rate_limit", true, func() bool {
				ok, _, _ := limiter.Check(ip)
				return ok
			})
			if !allowed {
				emitEvent(DetectionEvent{
					Type: "rate_limit", Severity: "medium",
					PatternID:   "rate_limit_exceeded",
					Description: "Rate limit exceeded for " + path,
					Route:       path, Method: method, Timestamp: nowMs(),
				}, m.config)
				return &pipelineEvent{statusCode: 429}
			}
		}
	}

	// Phase 2: Read body once
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

	// Phase 3: Tamper
	if m.config.TamperEnabled() && bodyMap != nil {
		var tamperEvents []DetectionEvent
		GuardedVoid(m.guard, "tamper", func() {
			tamperEvents = detectBusinessLogicTamper(bodyMap, m.config.FieldConstraints, path, method)
		})
		for _, d := range tamperEvents {
			emitEvent(d, m.config)
		}
		if m.config.StrictMode && len(tamperEvents) > 0 {
			return &pipelineEvent{statusCode: 400}
		}
	}

	// Phase 4: Input sanitize
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
					return &pipelineEvent{statusCode: 400}
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
			GuardedVoid(m.guard, "input_sanitize", func() {
				_, qd = sanitizeQuery(queryMap)
			})
			if len(qd) > 0 {
				for _, d := range qd {
					emitEvent(d, m.config)
				}
				if m.config.StrictMode {
					return &pipelineEvent{statusCode: 400}
				}
			}
		}
	}

	// Phase 5: SSRF
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
			return &pipelineEvent{statusCode: 403}
		}
	}

	// Phase 6: Prompt injection
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
			return &pipelineEvent{statusCode: 403}
		}
	}

	// Phase 7: BOLA
	if m.config.BOLAEnabled() {
		auth := headers.Get("authorization")
		token := ""
		if strings.HasPrefix(auth, "Bearer ") {
			token = auth[7:]
		}
		var bolaEvent *DetectionEvent
		GuardedVoid(m.guard, "bola", func() {
			tokenClaims := extractTokenClaims(token)
			template := routeTemplate
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
				return &pipelineEvent{statusCode: 404}
			}
		}
	}

	// Phase 8: Missing auth (advisory)
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

	return nil
}

func (m *GinMiddleware) SelfTest(port int) bool {
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
		sendTestResults(results, map[string]interface{}{"runtime": "gin", "port": port, "auto": true})
		return true
	}
	return false
}
