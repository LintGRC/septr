import type { SeptrConfig, DetectionEvent } from "../core/types"
import { buildBlockDetails, getDetectionLabels } from "../core/labels"
import { detectBOLA, extractRouteParams, extractRouteParamValues, extractTokenClaims, matchRouteTemplate } from "../core/bola"
import { SlidingWindowRateLimiter } from "../core/rate-limit"
import { stripSensitiveData } from "../core/strip"
import { detectMissingSecurityHeaders } from "../core/headers"
import { sanitizeInput, sanitizeQuery } from "../core/sanitize"
import { initTelemetry, emitEvent, sendTestResults } from "../core/telemetry"
import { startConfigPolling } from "../core/config-pull"
import { detectSSRF } from "../core/ssrf"
import { detectPromptInjection } from "../core/prompt-injection"
import { detectMissingAuth } from "../core/missing-auth"
import { detectBusinessLogicTamper } from "../core/tamper"
import { detectAIRateLimit } from "../core/ai-rate-limit"
import { extractTenantFromJwt, detectCrossTenantLeaks } from "../core/tenant-aware"
import { runEngineSelfTest, scheduleStartupSelfTest } from "../core/self-test"

type HonoContext = {
  req: {
    header: (name: string) => string | undefined
    method: string
    path: string
    routePath: string
    raw: { body: unknown }
    json: () => Promise<unknown>
    query: () => Record<string, string | string[]>
  }
  res: Response
  json: (body: unknown, status?: number) => Response
  newResponse: (body: BodyInit | null, status?: number, headers?: Record<string, string>) => Response
}

type HonoNext = () => Promise<void>

function extractAuthToken(ctx: HonoContext): string | null {
  const auth = ctx.req.header("authorization")
  if (!auth) return null
  return auth.replace(/^Bearer\s+/i, "")
}

function getClientIp(ctx: HonoContext): string {
  const forwarded = ctx.req.header("x-forwarded-for")
  if (forwarded) return forwarded.split(",")[0].trim()
  return "unknown"
}

function isAuthRoute(path: string): boolean {
  return ["/auth", "/login", "/checkout", "/register"].some((r) => path.startsWith(r))
}

/** Create Septr protection for Hono that intercepts requests and responses for all security features. */
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
    initTelemetry(config, pid, "hono")
    scheduleStartupSelfTest(config)
  }
  startConfigPolling(config)

  let selfTestResolve: (() => void) | null = null
  const selfTestToken = `vs_st_${Math.random().toString(36).slice(2, 10)}`

  async function vibeShieldMiddleware(ctx: HonoContext, next: HonoNext): Promise<Response | void> {
    if (ctx.req.routePath === "/__septr_ping" && ctx.req.header("x-septr-self-test") === selfTestToken) {
      selfTestResolve?.()
      selfTestResolve = null
      if (config.secrets) {
        const testBody = { api_key: "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", status: "ok" }
        const { cleaned, detections: stripDetections } = stripSensitiveData(testBody, config.stripFields)
        return ctx.newResponse(JSON.stringify(cleaned), 200, {
          "Content-Type": "application/json",
          "X-Septr-Stripped": String(stripDetections.length),
        })
      }
      return ctx.json({ status: "ok" }, 200)
    }

    const detections: DetectionEvent[] = []

    if (config.rateLimit && ctx.req.routePath !== "/__septr_ping") {
      const limiter = isAuthRoute(ctx.req.routePath) && ["POST", "PUT", "PATCH"].includes(ctx.req.method) ? authLimiter! : generalLimiter!
      const ip = getClientIp(ctx)
      const result = limiter.check(ip)

      if (!result.allowed) {
        const rlLabels = getDetectionLabels("rate_limit")
        emitEvent({
          type: "rate_limit",
          severity: "medium",
          patternId: "rate_limit_exceeded",
          description: `Rate limit exceeded for ${ctx.req.routePath}`,
          route: ctx.req.routePath,
          method: ctx.req.method,
          timestamp: Date.now(),
        }, config)
        return ctx.json({ error: "Too many requests", details: { type: "rate_limit", severity: "medium", location: ip, pattern: "rate_limit_exceeded", owasp: rlLabels.owasp, cwe: rlLabels.cwe, description: "Too many requests — rate limit exceeded", remediation: rlLabels.remediation } }, 429)
      }
    }

    if (config.inputSanitize) {
      if (["POST", "PUT", "PATCH", "DELETE"].includes(ctx.req.method)) {
        try {
          const body = await ctx.req.json()
          const { block, detections: sanitizeDetections } = sanitizeInput(body)
          detections.push(...sanitizeDetections)
          for (const d of sanitizeDetections) emitEvent(d, config)
          if (block && config.strictMode) {
            return ctx.json({ error: "Request blocked by Septr security filter", details: buildBlockDetails(sanitizeDetections[0]) }, 400)
          }
        } catch {
          // body not parseable as JSON
        }
      }

      const query = ctx.req.query?.() ?? {}
      if (query && Object.keys(query).length > 0) {
        const { block, detections: qd } = sanitizeQuery(query)
        detections.push(...qd)
        for (const d of qd) emitEvent(d, config)
        if (block && config.strictMode) {
          return ctx.json({ error: "Request blocked by Septr security filter", details: buildBlockDetails(qd[0]) }, 400)
        }
      }
    }

    if (config.tamper && ["POST", "PUT", "PATCH"].includes(ctx.req.method)) {
      try {
        const body = await ctx.req.json()
        if (body && typeof body === "object") {
          const tamperEvents = detectBusinessLogicTamper(body as Record<string, unknown>, config.fieldConstraints, ctx.req.routePath, ctx.req.method)
          for (const d of tamperEvents) {
            detections.push(d)
            emitEvent(d, config)
          }
          if (tamperEvents.length > 0 && config.strictMode) {
            return ctx.json({ error: "Business logic tamper detected by Septr", details: buildBlockDetails(tamperEvents[0]) }, 400)
          }
        }
      } catch {
        // body not parseable as JSON
      }
    }

    if (config.bola) {
      const token = extractAuthToken(ctx)
      const tokenClaims = token ? extractTokenClaims(token) : {}
      // In wildcard middleware (`app.use("*")`) Hono's `routePath` is the
      // middleware pattern, not the matched route — fall back to configured
      // route templates so BOLA can still resolve the real params.
      const routePath = ctx.req.routePath
      const template =
        routePath && routePath !== "/*" && routePath !== "*"
          ? routePath
          : config.bolaRouteTemplates?.length
            ? matchRouteTemplate(ctx.req.path, config.bolaRouteTemplates)
            : null
      const routeForEvent = template || ctx.req.path
      const routeParams = template ? extractRouteParams(template) : extractRouteParams(ctx.req.path)
      const routeParamValues = template && ctx.req.path ? extractRouteParamValues(template, ctx.req.path) : undefined

      const bolaEvent = detectBOLA(routeParams, null, tokenClaims, routeForEvent, ctx.req.method, routeParamValues)
      if (bolaEvent) {
        detections.push(bolaEvent)
        for (const d of detections) emitEvent(d, config)
        if (config.strictMode) {
          return ctx.newResponse(null, 404)
        }
      }
    }

    // SSRF detection
    if (config.ssrf) {
      const ssrfInputs: string[] = []
      if (ctx.req.routePath) ssrfInputs.push(ctx.req.routePath)
      try {
      const query = ctx.req.query?.() ?? {}
        if (query) ssrfInputs.push(JSON.stringify(query))
      } catch { /* query not available */ }
      try {
        const body = await ctx.req.json()
        ssrfInputs.push(typeof body === "string" ? body : JSON.stringify(body))
      } catch { /* body not JSON */ }
      const ssrfInput = ssrfInputs.join(" ")
      if (ssrfInput) {
        const ssrfEvents = detectSSRF(ssrfInput)
        for (const d of ssrfEvents) {
          detections.push(d)
          emitEvent(d, config)
        }
        if (ssrfEvents.length > 0 && config.strictMode) {
          return ctx.json({ error: "SSRF detected by Septr", details: buildBlockDetails(ssrfEvents[0]) }, 403)
        }
      }
    }

    // Prompt injection detection
    if (config.promptInjection) {
      try {
        const body = await ctx.req.json()
        const piInput = typeof body === "string" ? body : JSON.stringify(body)
        const piEvents = detectPromptInjection(piInput)
        for (const d of piEvents) {
          detections.push(d)
          emitEvent(d, config)
        }
        if (piEvents.length > 0 && config.strictMode) {
          return ctx.json({ error: "Prompt injection detected by Septr", details: buildBlockDetails(piEvents[0]) }, 403)
        }
      } catch {
        // body not parseable as JSON
      }
    }

    // Missing auth detection
    const authEvent = detectMissingAuth(
      ctx.req.routePath,
      ctx.req.method,
      ctx.req.header("authorization"),
    )
    if (authEvent) {
      detections.push(authEvent)
      emitEvent(authEvent, config)
    }

    await next()

    if (config.tenantAware && ctx.res) {
      const taConfig = config.tenantAware
      const token = extractAuthToken(ctx)
      if (token) {
        const claims = extractTokenClaims(token)
        const tenantId = extractTenantFromJwt(claims, taConfig.jwtClaim)
        if (tenantId) {
          try {
            const body = await ctx.res.clone().json()
            const leaks = detectCrossTenantLeaks(tenantId, body, taConfig.tenantColumn)
            if (leaks.length > 0) {
              const ctEvent: DetectionEvent = {
                type: "cross_tenant_leak",
                severity: "high",
                patternId: "tenant-aware-001",
                description: `Cross-tenant data leak: JWT ${taConfig.jwtClaim}=${tenantId}, response contained ${taConfig.tenantColumn}=${leaks[0].value} at ${leaks[0].path}`,
                route: ctx.req.routePath,
                method: ctx.req.method,
                timestamp: Date.now(),
              }
              for (const leak of leaks) {
                emitEvent({
                  type: "cross_tenant_leak",
                  severity: "high",
                  patternId: "tenant-aware-001",
                  description: `Cross-tenant data leak: JWT ${taConfig.jwtClaim}=${tenantId}, response contained ${taConfig.tenantColumn}=${leak.value} at ${leak.path}`,
                  route: ctx.req.routePath,
                  method: ctx.req.method,
                  timestamp: Date.now(),
                }, config)
              }
              if (taConfig.blockOnMismatch) {
                ctx.res = new Response(JSON.stringify({
                  error: "Cross-tenant data leak detected by Septr",
                  details: buildBlockDetails(ctEvent),
                }), { status: 403, headers: { "content-type": "application/json" } })
                return
              }
            }
          } catch {
            // non-JSON response, skip
          }
        }
      }
    }

    if (ctx.res && !["/__septr_ping"].includes(ctx.req.routePath)) {
      // Advisory: report responses missing standard security headers.
      for (const d of detectMissingSecurityHeaders(ctx.res.headers)) {
        emitEvent(d, config)
      }
    }

    if (config.secrets && ctx.res) {
      try {
        const contentLength = Number(ctx.res.headers.get("content-length") || 0)
        if (contentLength > 1_000_000) {
          // skip response inspection for large payloads
        } else {
          const body = await ctx.res.clone().json()
          if (config.aiRateLimit) {
            const aiEvents = detectAIRateLimit(JSON.stringify(body), ctx.req.routePath, ctx.req.method)
            for (const d of aiEvents) emitEvent(d, config)
          }
          const { cleaned, detections: stripDetections } = stripSensitiveData(body, config.stripFields)
          for (const d of stripDetections) emitEvent(d, config)
          if (stripDetections.length > 0) {
            const newHeaders = new Headers(ctx.res.headers)
            newHeaders.set("X-Septr-Stripped", String(stripDetections.length))
            ctx.res = ctx.newResponse(JSON.stringify(cleaned), ctx.res.status, Object.fromEntries(newHeaders))
          }
        }
      } catch {
        // body not JSON
      }
    }
  }

  vibeShieldMiddleware.selfTest = async (server: { address: () => { address: string; port: number } | string | null }): Promise<boolean> => {
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
        sendTestResults(engineResults, { runtime: "hono", port: addr.port })
      }
      return pipelineWorks && responseInPipeline
    } catch {
      return false
    } finally {
      clearTimeout(timeout)
    }
  }

  return vibeShieldMiddleware
}
