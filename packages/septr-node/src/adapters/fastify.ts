import type { SeptrConfig, DetectionEvent } from "../core/types"
import { buildBlockDetails, getDetectionLabels } from "../core/labels"
import { detectBOLA, extractRouteParams, extractRouteParamValues, extractTokenClaims } from "../core/bola"
import { SlidingWindowRateLimiter } from "../core/rate-limit"
import { stripSensitiveData } from "../core/strip"
import { detectMissingSecurityHeaders } from "../core/headers"
import { sanitizeInput, sanitizeQuery, detectSQLi, detectXSS } from "../core/sanitize"
import { initTelemetry, emitEvent, sendTestResults } from "../core/telemetry"
import { startConfigPolling } from "../core/config-pull"
import { detectSecrets } from "../core/secrets"
import { detectSSRF } from "../core/ssrf"
import { detectPromptInjection } from "../core/prompt-injection"
import { detectMissingAuth } from "../core/missing-auth"
import { detectBusinessLogicTamper } from "../core/tamper"
import { detectAIRateLimit } from "../core/ai-rate-limit"
import { extractTenantFromJwt, detectCrossTenantLeaks } from "../core/tenant-aware"
import { scheduleStartupSelfTest } from "../core/self-test"

type FastifyRequest = {
  method: string
  url: string
  routeOptions: { url: string | undefined }
  headers: Record<string, string | string[] | undefined>
  query?: Record<string, string | string[]>
  body?: unknown
}

type FastifyReply = {
  statusCode: number
  code: (statusCode: number) => FastifyReply
  header: (key: string, val: string) => void
  send: (body?: unknown) => void
  getHeaders?: () => Record<string, string | string[] | undefined>
}

type PreSerializationPayload = unknown

function extractAuthToken(headers: Record<string, string | string[] | undefined>): string | null {
  const auth = headers.authorization
  if (!auth) return null
  if (Array.isArray(auth)) return auth[0].replace(/^Bearer\s+/i, "")
  return auth.replace(/^Bearer\s+/i, "")
}

function getClientIp(headers: Record<string, string | string[] | undefined>): string {
  const forwarded = headers["x-forwarded-for"]
  if (forwarded) return (Array.isArray(forwarded) ? forwarded[0] : forwarded).split(",")[0].trim()
  return "unknown"
}

function isAuthRoute(path: string): boolean {
  return ["/auth", "/login", "/checkout", "/register"].some((r) => path.startsWith(r))
}

/** Create Fastify plugin hooks (`onRequest` + `preHandler` + `preSerialization`) for all Septr security features.
 *
 * Body-dependent engines (input sanitize, tamper, SSRF, prompt injection) run
 * in `preHandler` — Fastify parses the request body at `preHandler`, so
 * `request.body` is `undefined` in `onRequest`. Register all three hooks:
 * `app.addHook("onRequest", septr.onRequest)` /
 * `app.addHook("preHandler", septr.preHandler)` /
 * `app.addHook("preSerialization", septr.preSerialization)`. */
export function createSeptr(userConfig: SeptrConfig = {}) {
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
    initTelemetry(config, pid, "fastify")
    scheduleStartupSelfTest(config)
  }
  startConfigPolling(config)

  let selfTestResolve: (() => void) | null = null
  const selfTestToken = `vs_st_${Math.random().toString(36).slice(2, 10)}`

  return {
    onRequest: async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      if (request.url === "/__septr_ping" && request.headers["x-septr-self-test"] === selfTestToken) {
        selfTestResolve?.()
        selfTestResolve = null
        reply.send({ api_key: "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", status: "ok" })
        return
      }

      const detections: DetectionEvent[] = []

      if (config.rateLimit && request.url !== "/__septr_ping") {
        const limiter = isAuthRoute(request.url) && ["POST", "PUT", "PATCH"].includes(request.method) ? authLimiter! : generalLimiter!
        const ip = getClientIp(request.headers)
        const result = limiter.check(ip)

        reply.header("X-RateLimit-Limit", String(result.allowed ? limiter.max : 0))
        reply.header("X-RateLimit-Remaining", String(result.remaining))
        reply.header("X-RateLimit-Reset", String(result.resetMs))

        if (!result.allowed) {
          reply.header("Retry-After", String(Math.ceil(result.resetMs / 1000)))
          const rlLabels = getDetectionLabels("rate_limit")
          emitEvent({
            type: "rate_limit",
            severity: "medium",
            patternId: "rate_limit_exceeded",
            description: `Rate limit exceeded for ${request.url}`,
            route: request.url,
            method: request.method,
            timestamp: Date.now(),
          }, config)
          reply.code(429)
          reply.send({ error: "Too many requests", details: { type: "rate_limit", severity: "medium", location: ip, pattern: "rate_limit_exceeded", owasp: rlLabels.owasp, cwe: rlLabels.cwe, description: "Too many requests — rate limit exceeded", remediation: rlLabels.remediation } })
          return
        }
      }

      if (config.inputSanitize) {
        if (request.query && Object.keys(request.query).length > 0) {
          const { block, detections: qd } = sanitizeQuery(request.query)
          detections.push(...qd)
          for (const d of qd) emitEvent(d, config)
          if (block && config.strictMode) {
            reply.code(400)
            reply.send({ error: "Request blocked by Septr security filter", details: buildBlockDetails(qd[0]) })
            return
          }
        }
      }

      if (config.bola) {
        const token = extractAuthToken(request.headers)
        const tokenClaims = token ? extractTokenClaims(token) : {}
        const routePath = request.routeOptions?.url || request.url
        const routeParams = extractRouteParams(routePath)
        const routeParamValues = extractRouteParamValues(routePath, request.url)

        const bolaEvent = detectBOLA(routeParams, null, tokenClaims, routePath, request.method, routeParamValues)
      if (bolaEvent) {
        detections.push(bolaEvent)
        for (const d of detections) emitEvent(d, config)
        if (config.strictMode) {
          reply.code(404).send()
          return
        }
      }
    }

    // SSRF detection
    if (config.ssrf) {
      const ssrfInputs: string[] = []
      if (request.url) ssrfInputs.push(request.url)
      if (request.query) ssrfInputs.push(JSON.stringify(request.query))
      if (request.body && typeof request.body === "string") ssrfInputs.push(request.body)
      else if (request.body && typeof request.body === "object") ssrfInputs.push(JSON.stringify(request.body))
      const ssrfInput = ssrfInputs.join(" ")
      if (ssrfInput) {
        const ssrfEvents = detectSSRF(ssrfInput)
        for (const d of ssrfEvents) {
          detections.push(d)
          emitEvent(d, config)
        }
        if (ssrfEvents.length > 0 && config.strictMode) {
          reply.code(403)
          reply.send({ error: "SSRF detected by Septr", details: buildBlockDetails(ssrfEvents[0]) })
          return
        }
      }
    }

    // Prompt injection detection
    if (config.promptInjection) {
      const piInputs: string[] = []
      if (request.body && typeof request.body === "string") piInputs.push(request.body)
      else if (request.body && typeof request.body === "object") piInputs.push(JSON.stringify(request.body))
      if (request.query) piInputs.push(JSON.stringify(request.query))
      const piInput = piInputs.join(" ")
      if (piInput) {
        const piEvents = detectPromptInjection(piInput)
        for (const d of piEvents) {
          detections.push(d)
          emitEvent(d, config)
        }
        if (piEvents.length > 0 && config.strictMode) {
          reply.code(403)
          reply.send({ error: "Prompt injection detected by Septr", details: buildBlockDetails(piEvents[0]) })
          return
        }
      }
    }

    // Missing auth detection
    const authEvent = detectMissingAuth(
      request.url,
      request.method,
      Array.isArray(request.headers.authorization) ? request.headers.authorization[0] : request.headers.authorization,
    )
    if (authEvent) {
      detections.push(authEvent)
      emitEvent(authEvent, config)
    }

    if (config.tenantAware) {
      const taConfig = config.tenantAware
      const authHeader = Array.isArray(request.headers.authorization) ? request.headers.authorization[0] : request.headers.authorization
      if (authHeader?.startsWith("Bearer ")) {
        const claims = extractTokenClaims(authHeader.slice(7))
        const tenantId = extractTenantFromJwt(claims, taConfig.jwtClaim)
        if (tenantId) {
          ;(request as any).__vs_tenant_id = tenantId
          ;(request as any).__vs_tenant_config = taConfig
        }
      }
    }
    },

    /** Runs body-dependent engines (input sanitize, tamper, SSRF, prompt
     * injection) after Fastify has parsed the request body (preHandler phase). */
    preHandler: async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const detections: DetectionEvent[] = []

      if (config.inputSanitize) {
        if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) && request.body) {
          const { block, detections: sanitizeDetections } = sanitizeInput(request.body)
          detections.push(...sanitizeDetections)
          for (const d of sanitizeDetections) emitEvent(d, config)
          if (block && config.strictMode) {
            reply.code(400)
            reply.send({ error: "Request blocked by Septr security filter", details: buildBlockDetails(sanitizeDetections[0]) })
            return
          }
        }
      }

      if (config.tamper && request.body && typeof request.body === "object" && ["POST", "PUT", "PATCH"].includes(request.method)) {
        const tamperEvents = detectBusinessLogicTamper(request.body as Record<string, unknown>, config.fieldConstraints, request.url, request.method)
        for (const d of tamperEvents) {
          detections.push(d)
          emitEvent(d, config)
        }
        if (tamperEvents.length > 0 && config.strictMode) {
          reply.code(400)
          reply.send({ error: "Business logic tamper detected by Septr", details: buildBlockDetails(tamperEvents[0]) })
          return
        }
      }

      if (config.ssrf) {
        const ssrfInputs: string[] = []
        if (request.body && typeof request.body === "string") ssrfInputs.push(request.body)
        else if (request.body && typeof request.body === "object") ssrfInputs.push(JSON.stringify(request.body))
        const ssrfInput = ssrfInputs.join(" ")
        if (ssrfInput) {
          const ssrfEvents = detectSSRF(ssrfInput)
          for (const d of ssrfEvents) {
            detections.push(d)
            emitEvent(d, config)
          }
          if (ssrfEvents.length > 0 && config.strictMode) {
            reply.code(403)
            reply.send({ error: "SSRF detected by Septr", details: buildBlockDetails(ssrfEvents[0]) })
            return
          }
        }
      }

      if (config.promptInjection) {
        const piInputs: string[] = []
        if (request.body && typeof request.body === "string") piInputs.push(request.body)
        else if (request.body && typeof request.body === "object") piInputs.push(JSON.stringify(request.body))
        const piInput = piInputs.join(" ")
        if (piInput) {
          const piEvents = detectPromptInjection(piInput)
          for (const d of piEvents) {
            detections.push(d)
            emitEvent(d, config)
          }
          if (piEvents.length > 0 && config.strictMode) {
            reply.code(403)
            reply.send({ error: "Prompt injection detected by Septr", details: buildBlockDetails(piEvents[0]) })
            return
          }
        }
      }
    },

    preSerialization: (request: FastifyRequest, reply: FastifyReply, payload: PreSerializationPayload, done: (err?: Error | null, newPayload?: unknown) => void): void => {
      try {
        // Advisory: report responses missing standard security headers.
        if (typeof reply.getHeaders === "function") {
          for (const d of detectMissingSecurityHeaders(reply.getHeaders() as Record<string, string>)) {
            emitEvent(d, config)
          }
        }
        const tenantId = (request as any).__vs_tenant_id
        const taConfig = (request as any).__vs_tenant_config
        if (tenantId && taConfig && payload) {
          const leaks = detectCrossTenantLeaks(tenantId, payload, taConfig.tenantColumn)
          if (leaks.length > 0) {
            const ctEvent: DetectionEvent = {
              type: "cross_tenant_leak",
              severity: "high",
              patternId: "tenant-aware-001",
              description: `Cross-tenant data leak: JWT ${taConfig.jwtClaim}=${tenantId}, response contained ${taConfig.tenantColumn}=${leaks[0].value} at ${leaks[0].path}`,
              route: request.url,
              method: request.method,
              timestamp: Date.now(),
            }
            for (const leak of leaks) {
              emitEvent({
                type: "cross_tenant_leak",
                severity: "high",
                patternId: "tenant-aware-001",
                description: `Cross-tenant data leak: JWT ${taConfig.jwtClaim}=${tenantId}, response contained ${taConfig.tenantColumn}=${leak.value} at ${leak.path}`,
                route: request.url,
                method: request.method,
                timestamp: Date.now(),
              }, config)
            }
            if (taConfig.blockOnMismatch) {
              reply.code(403)
              done(null, { error: "Cross-tenant data leak detected by Septr", details: buildBlockDetails(ctEvent) })
              return
            }
          }
        }

        if ((!config.secrets && !config.aiRateLimit) || !payload) {
          done(null, payload)
          return
        }

        const serialized = typeof payload === "string" ? payload : JSON.stringify(payload)
        if (serialized.length > 1_000_000) {
          done(null, payload)
          return
        }

        if (config.aiRateLimit) {
          const aiEvents = detectAIRateLimit(serialized, request.url, request.method)
          for (const d of aiEvents) emitEvent(d, config)
        }

        if (!config.secrets) {
          done(null, payload)
          return
        }

        const { cleaned, detections: stripDetections } = stripSensitiveData(payload, config.stripFields)
        if (request.url !== "/__septr_ping") {
          for (const d of stripDetections) emitEvent(d, config)
        }
        if (stripDetections.length > 0) {
          reply.header("X-Septr-Stripped", String(stripDetections.length))
        }
        done(null, cleaned)
      } catch (err) {
        done(err as Error, payload)
      }
    },

    selfTest: async (server: { address: () => { address: string; port: number } | string | null }): Promise<boolean> => {
      const addr = server.address()
      if (!addr || typeof addr === "string") return false
      const host = addr.address === "0.0.0.0" || addr.address === "::" ? "127.0.0.1" : addr.address

      let secretsWorks = false
      let sqliWorks = false
      let xssWorks = false
      let bolaWorks = false
      let ssrfWorks = false
      let piWorks = false
    let missingAuthWorks = false
    let tamperWorks = false
    try {
      secretsWorks = detectSecrets("sk_test_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", []).length > 0
      } catch { secretsWorks = false }
      try {
        sqliWorks = detectSQLi("1' OR '1'='1").length > 0
      } catch { sqliWorks = false }
      try {
        xssWorks = detectXSS("<script>alert(1)</script>").length > 0
      } catch { xssWorks = false }
      try {
        bolaWorks = detectBOLA(["userId"], null, { sub: "42" }, "/users/:userId", "GET") !== null
      } catch { bolaWorks = false }
      try {
        ssrfWorks = detectSSRF("http://169.254.169.254/latest/meta-data/").length > 0
      } catch { ssrfWorks = false }
      try {
        piWorks = detectPromptInjection("Ignore previous instructions").length > 0
      } catch { piWorks = false }
    try {
      missingAuthWorks = detectMissingAuth("/api/users", "GET", undefined) !== null
    } catch { missingAuthWorks = false }
    try {
      tamperWorks = detectBusinessLogicTamper({ amount: -100 }).length > 0
    } catch { tamperWorks = false }

    const pipelineWorks = secretsWorks && sqliWorks && xssWorks && bolaWorks && ssrfWorks && piWorks && missingAuthWorks && tamperWorks

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
          sendTestResults([
            { engine: "secrets", passed: secretsWorks },
            { engine: "sqli", passed: sqliWorks },
            { engine: "xss", passed: xssWorks },
            { engine: "bola", passed: bolaWorks },
            { engine: "ssrf", passed: ssrfWorks },
            { engine: "prompt_injection", passed: piWorks },
            { engine: "missing_auth", passed: missingAuthWorks },
            { engine: "tamper", passed: tamperWorks },
          ], { runtime: "fastify", port: addr.port })
        }
        return pipelineWorks && responseInPipeline
      } catch {
        return false
      } finally {
        clearTimeout(timeout)
      }
    },
  }
}
