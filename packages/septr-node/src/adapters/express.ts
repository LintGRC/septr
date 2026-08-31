import type { SeptrConfig, DetectionEvent } from "../core/types"
import { buildBlockDetails, getDetectionLabels } from "../core/labels"
import { detectBOLA, extractRouteParams, extractRouteParamValues, extractTokenClaims, matchRouteTemplate } from "../core/bola"
import { SlidingWindowRateLimiter } from "../core/rate-limit"
import { stripSensitiveData } from "../core/strip"
import { detectMissingSecurityHeaders } from "../core/headers"
import { initTelemetry, emitEvent, sendTestResults } from "../core/telemetry"
import { startConfigPolling } from "../core/config-pull"
import { detectSecrets } from "../core/secrets"
import { sanitizeInput, sanitizeQuery } from "../core/sanitize"
import { detectSSRF } from "../core/ssrf"
import { detectPromptInjection } from "../core/prompt-injection"
import { detectMissingAuth } from "../core/missing-auth"
import { detectBusinessLogicTamper } from "../core/tamper"
import { detectAIRateLimit } from "../core/ai-rate-limit"
import { extractTenantFromJwt, detectCrossTenantLeaks } from "../core/tenant-aware"
import { runEngineSelfTest, scheduleStartupSelfTest } from "../core/self-test"
import type { RequestHandler } from "express"

type NextFunction = (err?: unknown) => void
type Request = { method: string; path: string; headers: Record<string, string | string[] | undefined>; body?: unknown; query?: Record<string, string | string[]> }
type Response = {
  json: (body: unknown) => void
  send: (body: unknown) => void
  setHeader: (key: string, val: string) => void
  status: (code: number) => Response
  end: () => void
  locals?: Record<string, unknown>
  getHeaders?: () => Record<string, string | string[] | undefined>
}

/** createSeptr return type: a callable Express middleware with a selfTest
 * helper attached. The call signature must be assignable to
 * `express.RequestHandler` so `app.use(createSeptr(...))` typechecks. */
export interface SeptrExpressMiddleware extends RequestHandler {
  selfTest(server: { address: () => { address: string; port: number } | string | null }): Promise<boolean>
}

function extractAuthToken(headers: Record<string, string | string[] | undefined>): string | null {
  const auth = headers.authorization
  if (!auth) return null
  return Array.isArray(auth) ? auth[0] : auth.replace(/^Bearer\s+/i, "")
}

function getClientIp(headers: Record<string, string | string[] | undefined>): string {
  const forwarded = headers["x-forwarded-for"]
  if (forwarded) return Array.isArray(forwarded) ? forwarded[0] : forwarded.split(",")[0].trim()
  return "unknown"
}

function isAuthRoute(path: string): boolean {
  return ["/auth", "/login", "/checkout", "/register"].some((r) => path.startsWith(r))
}

/** Resolve the matched route template (e.g. `/api/users/:userId`) by walking the
 * Express router stack — the route isn't matched yet at middleware time, but the
 * registered route list tells us the template for this concrete path. */
function resolveExpressTemplate(req: any): string | null {
  const app = req?.app
  const stack = app?._router?.stack ?? app?.router?.stack
  if (!Array.isArray(stack)) return null
  const method = String(req.method ?? "").toLowerCase()
  const templates: string[] = []
  for (const layer of stack) {
    const route = layer?.route
    if (!route?.path || typeof route.path !== "string") continue
    const routeMethods = route.methods
    const matchesMethod = routeMethods
      ? typeof routeMethods.has === "function"
        ? routeMethods.has(method)
        : routeMethods[method] === true
      : true
    if (!matchesMethod) continue
    templates.push(route.path)
  }
  return matchRouteTemplate(req.path ?? "", templates)
}

/** Create Septr protection that intercepts requests and responses for secret detection, BOLA/IDOR protection, rate limiting, input sanitization, and response data stripping. */
export function createSeptr(userConfig: SeptrConfig = {}): SeptrExpressMiddleware {
  const config: SeptrConfig = {
    secrets: true,
    bola: true,
    rateLimit: true,
    inputSanitize: true,
    ssrf: true,
    promptInjection: true,
    tamper: true,
    telemetry: false,
    ...userConfig,
  }

  const generalLimiter = config.rateLimit
    ? new SlidingWindowRateLimiter(
        config.rateLimitConfig?.max ?? 60,
        config.rateLimitConfig?.windowMs ?? 60_000,
      )
    : null

  const authLimiter = config.rateLimit
    ? new SlidingWindowRateLimiter(10, 60_000)
    : null

  if (config.apiKey && config.telemetry !== false) {
    const pid = config.projectId || config.apiKey
    initTelemetry(config, pid, "express")
    scheduleStartupSelfTest(config)
  }
  startConfigPolling(config)

  let selfTestResolve: (() => void) | null = null
  const selfTestToken = `vs_st_${Math.random().toString(36).slice(2, 10)}`

  function vibeShieldMiddleware(req: Request, res: Response, next: NextFunction): void {
    const originalJson = res.json.bind(res)
    const originalSend = res.send.bind(res)

    // Advisory: report responses missing standard security headers. Runs inside
    // the response patches (after the handler set its headers), once per response.
    let headersChecked = false
    const checkHeaders = (): void => {
      if (headersChecked || typeof res.getHeaders !== "function") return
      headersChecked = true
      for (const d of detectMissingSecurityHeaders(res.getHeaders())) {
        emitEvent(d, config)
      }
    }

    /** Skip response inspection for payloads over 1 MB. */
const MAX_INSPECT_BYTES = 1_000_000

  res.json = function (body: unknown): void {
      const isPing = req.path === "/__septr_ping"
      checkHeaders()
      if (config.secrets && body) {
        const serialized = JSON.stringify(body)
        if (serialized.length > MAX_INSPECT_BYTES) {
          originalJson(body)
          return
        }
        const { cleaned, detections: stripDetections } = stripSensitiveData(body, config.stripFields)
        if (!isPing) {
          for (const d of stripDetections) emitEvent(d, config)
          if (config.aiRateLimit) {
            const aiEvents = detectAIRateLimit(serialized, req.path, req.method)
            for (const d of aiEvents) emitEvent(d, config)
          }
        }
        if (stripDetections.length > 0) {
          res.setHeader("X-Septr-Stripped", String(stripDetections.length))
        }
        originalJson(cleaned)
      } else {
        originalJson(body)
      }
    }

    res.send = function (body: unknown): void {
      const isPing = req.path === "/__septr_ping"
      checkHeaders()
      if (config.secrets && typeof body === "object" && body !== null) {
        const serialized = JSON.stringify(body)
        if (serialized.length > MAX_INSPECT_BYTES) {
          originalSend(body)
          return
        }
        const { cleaned, detections: stripDetections } = stripSensitiveData(body, config.stripFields)
        if (!isPing) {
          for (const d of stripDetections) emitEvent(d, config)
          if (config.aiRateLimit) {
            const aiEvents = detectAIRateLimit(serialized, req.path, req.method)
            for (const d of aiEvents) emitEvent(d, config)
          }
        }
        if (stripDetections.length > 0) {
          res.setHeader("X-Septr-Stripped", String(stripDetections.length))
        }
        originalSend(cleaned)
      } else if (config.secrets && typeof body === "string") {
        if (body.length > MAX_INSPECT_BYTES) {
          originalSend(body)
          return
        }
        const secretDetections = detectSecrets(body, config.sensitivePatterns)
        if (!isPing) {
          for (const d of secretDetections) emitEvent(d, config)
          if (config.aiRateLimit) {
            const aiEvents = detectAIRateLimit(body, req.path, req.method)
            for (const d of aiEvents) emitEvent(d, config)
          }
        }
        if (secretDetections.length > 0) {
          originalSend("[REDACTED]")
          return
        }
        originalSend(body)
      } else {
        originalSend(body)
      }
    }

    if (res.locals?.vibeShieldSkip) {
      next()
      return
    }

    if (req.path === "/__septr_ping" && req.headers["x-septr-self-test"] === selfTestToken) {
      selfTestResolve?.()
      selfTestResolve = null
      res.json({ api_key: "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", status: "ok" })
      return
    }

    const detections: DetectionEvent[] = []

    if (config.rateLimit && req.path !== "/__septr_ping") {
      const limiter = isAuthRoute(req.path) && ["POST", "PUT", "PATCH"].includes(req.method) ? authLimiter! : generalLimiter!
      const ip = getClientIp(req.headers)
      const result = limiter.check(ip)

      res.setHeader("X-RateLimit-Limit", String(result.allowed ? limiter.max : 0))
      res.setHeader("X-RateLimit-Remaining", String(result.remaining))
      res.setHeader("X-RateLimit-Reset", String(result.resetMs))

      if (!result.allowed) {
        res.setHeader("Retry-After", String(Math.ceil(result.resetMs / 1000)))
        const rlLabels = getDetectionLabels("rate_limit")
        emitEvent({
          type: "rate_limit",
          severity: "medium",
          patternId: "rate_limit_exceeded",
          description: `Rate limit exceeded for ${req.path}`,
          route: req.path,
          method: req.method,
          timestamp: Date.now(),
        }, config)
        res.status(429).json({ error: "Too many requests", details: { type: "rate_limit", severity: "medium", location: ip, pattern: "rate_limit_exceeded", owasp: rlLabels.owasp, cwe: rlLabels.cwe, description: "Too many requests — rate limit exceeded", remediation: rlLabels.remediation } })
        return
      }
    }

    if (config.inputSanitize) {
      if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && req.body) {
        const { block, detections: sanitizeDetections } = sanitizeInput(req.body)
        detections.push(...sanitizeDetections)
        for (const d of sanitizeDetections) emitEvent(d, config)
        if (block && config.strictMode) {
          res.status(400).json({ error: "Request blocked by Septr security filter", details: buildBlockDetails(sanitizeDetections[0]) })
          return
        }
      }
    }

    if (config.inputSanitize && req.query) {
      const { block, detections: qd } = sanitizeQuery(req.query)
      detections.push(...qd)
      for (const d of qd) emitEvent(d, config)
      if (block && config.strictMode) {
        res.status(400).json({ error: "Request blocked by Septr security filter", details: buildBlockDetails(qd[0]) })
        return
      }
    }

    if (config.tamper && req.body && typeof req.body === "object" && ["POST", "PUT", "PATCH"].includes(req.method)) {
      const tamperEvents = detectBusinessLogicTamper(req.body as Record<string, unknown>, config.fieldConstraints, req.path, req.method)
      for (const d of tamperEvents) {
        detections.push(d)
        emitEvent(d, config)
      }
      if (tamperEvents.length > 0 && config.strictMode) {
        res.status(400).json({ error: "Business logic tamper detected by Septr", details: buildBlockDetails(tamperEvents[0]) })
        return
      }
    }

    if (config.bola) {
      const token = extractAuthToken(req.headers)
      const tokenClaims = token ? extractTokenClaims(token) : {}
      const template = resolveExpressTemplate(req)
      const routeForEvent = template || req.path
      const routeParams = template ? extractRouteParams(template) : extractRouteParams(req.path)
      const routeParamValues = template ? extractRouteParamValues(template, req.path) : undefined
      const bodyParams = req.body as Record<string, string> | undefined

      const bolaEvent = detectBOLA(routeParams, bodyParams ?? null, tokenClaims, routeForEvent, req.method, routeParamValues)
      if (bolaEvent) {
        detections.push(bolaEvent)
        for (const d of detections) emitEvent(d, config)
        if (config.strictMode) {
          res.status(404).end()
          return
        }
      }
    }

    // Missing auth detection: flag unprotected routes
    const authEvent = detectMissingAuth(
      req.path,
      req.method,
      Array.isArray(req.headers.authorization) ? req.headers.authorization[0] : req.headers.authorization,
    )
    if (authEvent) {
      detections.push(authEvent)
      emitEvent(authEvent, config)
    }

    // SSRF detection: scan URL, body, and query for internal IP / cloud metadata patterns
    if (config.ssrf) {
      const ssrfInputs: string[] = []
      if (req.path) ssrfInputs.push(req.path)
      if (req.query) ssrfInputs.push(JSON.stringify(req.query))
      if (req.body && typeof req.body === "string") ssrfInputs.push(req.body)
      else if (req.body && typeof req.body === "object") ssrfInputs.push(JSON.stringify(req.body))

      const ssrfInput = ssrfInputs.join(" ")
      if (ssrfInput) {
        const ssrfEvents = detectSSRF(ssrfInput)
        for (const d of ssrfEvents) {
          detections.push(d)
          emitEvent(d, config)
        }
        if (ssrfEvents.length > 0 && config.strictMode) {
          res.status(403).json({ error: "SSRF detected by Septr", details: buildBlockDetails(ssrfEvents[0]) })
          return
        }
      }
    }

    // Prompt injection detection: scan body and query for LLM jailbreak patterns
    if (config.promptInjection) {
      const piInputs: string[] = []
      if (req.body && typeof req.body === "string") piInputs.push(req.body)
      else if (req.body && typeof req.body === "object") piInputs.push(JSON.stringify(req.body))
      if (req.query) piInputs.push(JSON.stringify(req.query))

      const piInput = piInputs.join(" ")
      if (piInput) {
        const piEvents = detectPromptInjection(piInput)
        for (const d of piEvents) {
          detections.push(d)
          emitEvent(d, config)
        }
        if (piEvents.length > 0 && config.strictMode) {
          res.status(403).json({ error: "Prompt injection detected by Septr", details: buildBlockDetails(piEvents[0]) })
          return
        }
      }
    }

    // Tenant-aware: detect cross-tenant data leaks in responses
    if (config.tenantAware) {
      const taConfig = config.tenantAware
      const token = extractAuthToken(req.headers)
      if (token) {
        const claims = extractTokenClaims(token)
        const tenantId = extractTenantFromJwt(claims, taConfig.jwtClaim)
        if (tenantId) {
          const origSend = res.send.bind(res)
          res.send = function (body: unknown) {
            if (typeof body === "string") {
              try {
                const parsed = JSON.parse(body)
                const leaks = detectCrossTenantLeaks(tenantId!, parsed, taConfig.tenantColumn)
                if (leaks.length > 0) {
                  const ctEvent: DetectionEvent = {
                    type: "cross_tenant_leak",
                    severity: "high",
                    patternId: "tenant-aware-001",
                    description: `Cross-tenant data leak: JWT ${taConfig.jwtClaim}=${tenantId}, response contained ${taConfig.tenantColumn}=${leaks[0].value} at ${leaks[0].path}`,
                    route: req.path,
                    method: req.method,
                    timestamp: Date.now(),
                  }
                  for (const leak of leaks) {
                    emitEvent({
                      type: "cross_tenant_leak",
                      severity: "high",
                      patternId: "tenant-aware-001",
                      description: `Cross-tenant data leak: JWT ${taConfig.jwtClaim}=${tenantId}, response contained ${taConfig.tenantColumn}=${leak.value} at ${leak.path}`,
                      route: req.path,
                      method: req.method,
                      timestamp: Date.now(),
                    }, config)
                  }
                  if (taConfig.blockOnMismatch) {
                    res.status(403)
                    return (origSend as Function).call(res, JSON.stringify({
                      error: "Cross-tenant data leak detected by Septr",
                      details: buildBlockDetails(ctEvent),
                    }))
                  }
                }
              } catch {
                // not JSON, skip
              }
            }
            return (origSend as Function).call(res, body)
          }
        }
      }
    }

    next()
  }

  vibeShieldMiddleware.selfTest = async function(server: { address: () => { address: string; port: number } | string | null }): Promise<boolean> {
    const addr = server.address()
    if (!addr || typeof addr === "string") return false
    const host = addr.address === "0.0.0.0" || addr.address === "::" ? "127.0.0.1" : addr.address

    const engineResults = runEngineSelfTest()
    const pipelineWorks = engineResults.every((r) => r.passed)

    const promise = new Promise<void>((resolve) => { selfTestResolve = resolve })
    const timeout = setTimeout(() => { selfTestResolve = null }, 5000)

    try {
      if (typeof fetch !== "function") return false
      const response = await fetch(`http://${host}:${addr.port}/__septr_ping`, {
        headers: { "x-septr-self-test": selfTestToken },
        signal: AbortSignal.timeout(4000),
      })
      await promise
      const stripped = response.headers.get("X-Septr-Stripped")
      const responseInPipeline = stripped !== null
      if (pipelineWorks && responseInPipeline) {
        sendTestResults(engineResults, { runtime: "express", port: addr.port })
      }
      return pipelineWorks && responseInPipeline
    } catch {
      return false
    } finally {
      clearTimeout(timeout)
    }
  }

  return vibeShieldMiddleware as unknown as SeptrExpressMiddleware
}
