import type { SeptrConfig, DetectionEvent } from "../core/types"
import { buildBlockDetails, getDetectionLabels } from "../core/labels"
import { sanitizeInput, sanitizeQuery } from "../core/sanitize"
import { detectBOLA, extractRouteParams, extractRouteParamValues, extractTokenClaims, matchRouteTemplate } from "../core/bola"
import { emitEvent } from "../core/telemetry"
import { stripSensitiveData } from "../core/strip"
import { detectMissingSecurityHeaders } from "../core/headers"
import { detectSSRF } from "../core/ssrf"
import { detectPromptInjection } from "../core/prompt-injection"
import { detectMissingAuth } from "../core/missing-auth"
import { detectBusinessLogicTamper } from "../core/tamper"
import { detectAIRateLimit, hasRateLimitHint } from "../core/ai-rate-limit"
import { runEngineSelfTest } from "../core/self-test"
import { EngineGuard, killSwitchEngaged } from "../core/safety"
type NextRequest = {
  nextUrl: { pathname: string; searchParams: URLSearchParams }
  headers: Headers
  method: string
  json: () => Promise<unknown>
}

type NextResponse = {
  status: number
  json: (body?: unknown) => NextResponse | Promise<unknown>
  headers: Headers
}

type NextMiddlewareResult = NextResponse | Response | void

function extractAuthToken(headers: Headers): string | null {
  const auth = headers.get("authorization")
  if (!auth) return null
  return auth.replace(/^Bearer\s+/i, "")
}

function getClientIp(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for")
  if (forwarded) return forwarded.split(",")[0].trim()
  return "unknown"
}

function createRateLimiter(config: SeptrConfig) {
  const authRoutes = ["/auth", "/login", "/checkout", "/register"]
  const generalConfig = config.rateLimitConfig ?? { max: 60, windowMs: 60_000 }
  const strictConfig = { max: 10, windowMs: 60_000 }

  const store = new Map<string, { count: number; windowStart: number }>()

  function cleanup() {
    const now = Date.now()
    for (const [key, entry] of store) {
      if (now - entry.windowStart > generalConfig.windowMs) {
        store.delete(key)
      }
    }
  }

  return {
    check(key: string, route?: string, method?: string) {
      cleanup()
      const now = Date.now()
      const strict = route && method && ["POST", "PUT", "PATCH"].includes(method) && authRoutes.some((r) => route.startsWith(r))
      const cfg = strict ? strictConfig : generalConfig
      const entry = store.get(key)

      if (!entry || now - entry.windowStart > cfg.windowMs) {
        store.set(key, { count: 1, windowStart: now })
        return { allowed: true, remaining: cfg.max - 1, resetMs: cfg.windowMs, limit: cfg.max }
      }

      if (entry.count >= cfg.max) {
        return {
          allowed: false,
          remaining: 0,
          resetMs: cfg.windowMs - (now - entry.windowStart),
          limit: cfg.max,
        }
      }

      entry.count++
      return {
        allowed: true,
        remaining: cfg.max - entry.count,
        resetMs: cfg.windowMs - (now - entry.windowStart),
        limit: cfg.max,
      }
    },
  }
}

/**
 * IMPORTANT: This Edge protection runs before the response is generated.
 * It can do rate limiting and BOLA detection, but CANNOT scan outgoing
 * response bodies. For full response body secret stripping, use the
 * Express adapter or wrap individual API route handlers with `withSeptr()`.
 */
/** Create Next.js Edge protection for rate limiting and BOLA detection. Note: cannot scan response bodies in Edge runtime — use {@link withSeptr} for per-route protection. */
export function createSeptr(userConfig: SeptrConfig = {}) {
  const config: SeptrConfig = {
    secrets: true,
    bola: true,
    rateLimit: true,
    inputSanitize: true,
    ssrf: true,
    promptInjection: true,
    tamper: true,
    telemetry: true,
    ...userConfig,
  }

  const rateLimiter = config.rateLimit ? createRateLimiter(config) : null

  const guard = new EngineGuard({
    failureThreshold: config.engineFailureThreshold,
    budgetMs: config.engineBudgetMs,
    onDegraded: (engine, reason) => {
      emitEvent({
        type: "system",
        severity: "info",
        patternId: "engine_degraded",
        description: `Engine \`${engine}\` degraded and was disabled for this process (${reason}). Restart the app to retry, or upgrade the Septr SDK.`,
        timestamp: Date.now(),
      }, config)
    },
  })

  let selfTestDone = false

  return async function vibeShieldMiddleware(request: NextRequest): Promise<NextMiddlewareResult> {
    if (killSwitchEngaged(config)) return
    return await (async (): Promise<NextMiddlewareResult> => {
    if (!selfTestDone && config.selfTest !== false) {
      selfTestDone = true
      const engineResults = runEngineSelfTest()
      if (config.apiKey && config.telemetry !== false) {
        const { initTelemetry, sendTestResults, flushSync } = await import("../core/telemetry")
        // The manager is created lazily on the first detection — without an
        // explicit init here, self-test results would be dropped (sendTestResults
        // no-ops when no manager exists yet).
        const pid = config.projectId || config.apiKey
        initTelemetry(config, pid, "nextjs")
        sendTestResults(engineResults, { runtime: "nextjs", auto: true })
        // The edge isolate may die before the buffered self-test results
        // flush on the 30s timer — force the POST to complete now.
        await flushSync()
        const { startConfigPolling } = await import("../core/config-pull")
        await startConfigPolling(config)
      }
    }

    const detections: DetectionEvent[] = []

    if (config.rateLimit && rateLimiter) {
      const ip = getClientIp(request.headers)
      const result = rateLimiter.check(ip, request.nextUrl.pathname, request.method)

      if (!result.allowed) {
        detections.push({
          type: "rate_limit",
          severity: "medium",
          patternId: "rate_limit_exceeded",
          description: `Rate limit exceeded for ${request.nextUrl.pathname}`,
          route: request.nextUrl.pathname,
          method: request.method,
          timestamp: Date.now(),
        })
        if (config.apiKey && config.telemetry !== false) {
          const { initTelemetry, emitEvent } = await import("../core/telemetry")
          const pid = config.projectId || config.apiKey
          initTelemetry(config, pid, "nextjs")
          for (const d of detections) emitEvent(d, config)
        }
        if (config.apiKey && config.telemetry !== false) {
          const { flushSync } = await import("../core/telemetry")
          await flushSync()
        }
        const rlLabels = getDetectionLabels("rate_limit")
        return new Response(JSON.stringify({ error: "Too many requests", details: { type: "rate_limit", severity: "medium", location: ip, pattern: "rate_limit_exceeded", owasp: rlLabels.owasp, cwe: rlLabels.cwe, description: "Too many requests — rate limit exceeded", remediation: rlLabels.remediation } }), {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": String(Math.ceil(result.resetMs / 1000)),
            "X-RateLimit-Limit": String(result.limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": String(result.resetMs),
          },
        })
      }
    }

    let requestBodyText = ""
    try {
      requestBodyText = await (request as unknown as Request).text()
    } catch { /* body unreadable in edge runtime */ }

    if (config.inputSanitize && (request.nextUrl.searchParams.size > 0 || requestBodyText)) {
      const query: Record<string, string | string[]> = {}
      for (const [key, val] of request.nextUrl.searchParams.entries()) {
        const existing = query[key]
        if (existing === undefined) {
          query[key] = val
        } else if (Array.isArray(existing)) {
          existing.push(val)
        } else {
          query[key] = [existing, val]
        }
      }
      let qd: ReturnType<typeof sanitizeQuery>["detections"] = []
      let block = false
      if (request.nextUrl.searchParams.size > 0) {
        const r = guard.run("input_sanitize", () => sanitizeQuery(query), { block: false, detections: [] as DetectionEvent[] })
        qd = r.detections
        block = r.block
      }
      let bd: ReturnType<typeof sanitizeInput>["detections"] = []
      if (requestBodyText && ["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) {
        try {
          const parsed = JSON.parse(requestBodyText)
          const r = guard.run("input_sanitize", () => sanitizeInput(parsed), { block: false, detections: [] as DetectionEvent[] })
          bd = r.detections
          block = block || r.block
        } catch { /* body not JSON */ }
      }
      detections.push(...qd, ...bd)
      for (const d of [...qd, ...bd]) emitEvent(d, config)
      if (block && config.strictMode) {
        if (config.apiKey && config.telemetry !== false) {
          const { flushSync } = await import("../core/telemetry")
          await flushSync()
        }
        return new Response(JSON.stringify({ error: "Request blocked by Septr security filter", details: buildBlockDetails(([...qd, ...bd])[0]) }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        })
      }
    }

    if (config.bola) {
      const token = extractAuthToken(request.headers)
      const tokenClaims = token ? extractTokenClaims(token) : {}
      const pathname = request.nextUrl.pathname
      const template = config.bolaRouteTemplates?.length
        ? matchRouteTemplate(pathname, config.bolaRouteTemplates)
        : null
      const routeForEvent = template || pathname
      const routeParams = template ? extractRouteParams(template) : extractRouteParams(pathname)
      const routeParamValues = template ? extractRouteParamValues(template, pathname) : undefined

      const bolaEvent = guard.run("bola", () => detectBOLA(routeParams, null, tokenClaims, routeForEvent, request.method, routeParamValues), null)
      if (bolaEvent) {
        detections.push(bolaEvent)
        if (config.strictMode) {
          if (config.apiKey && config.telemetry !== false) {
            const { initTelemetry, emitEvent } = await import("../core/telemetry")
            const pid = config.projectId || config.apiKey
            initTelemetry(config, pid, "nextjs")
            for (const d of detections) emitEvent(d, config)
          }
        if (config.apiKey && config.telemetry !== false) {
          const { flushSync } = await import("../core/telemetry")
          await flushSync()
        }
          return new Response(null, { status: 404 })
        }
      }
    }

    // SSRF detection (Edge-safe: string matching)
    const ssrfInputs: string[] = [request.nextUrl.pathname]
    for (const [key, val] of request.nextUrl.searchParams.entries()) {
      ssrfInputs.push(`${key}=${val}`)
    }
    if (requestBodyText) {
      ssrfInputs.push(requestBodyText)
    }
    const ssrfInput = ssrfInputs.join(" ")
    if (ssrfInput) {
      const ssrfEvents = guard.run("ssrf", () => detectSSRF(ssrfInput), [] as DetectionEvent[])
      for (const d of ssrfEvents) {
        detections.push(d)
        if (config.apiKey && config.telemetry !== false) {
          const { initTelemetry, emitEvent } = await import("../core/telemetry")
          const pid = config.projectId || config.apiKey
          initTelemetry(config, pid, "nextjs")
          emitEvent(d, config)
        }
      }
        if (config.apiKey && config.telemetry !== false) {
          const { flushSync } = await import("../core/telemetry")
          await flushSync()
        }
      if (ssrfEvents.length > 0 && config.strictMode) {
        return new Response(JSON.stringify({ error: "SSRF detected by Septr", details: buildBlockDetails(ssrfEvents[0]) }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        })
      }
    }

    // Prompt injection detection (Edge-safe: string matching)
    let piInput = ""
    if (requestBodyText) {
      try {
        const body = JSON.parse(requestBodyText)
        piInput = typeof body === "string" ? body : requestBodyText
      } catch {
        piInput = requestBodyText
      }
    }
    if (piInput) {
      const piEvents = guard.run("prompt_injection", () => detectPromptInjection(piInput), [] as DetectionEvent[])
      for (const d of piEvents) {
        detections.push(d)
        if (config.apiKey && config.telemetry !== false) {
          const { initTelemetry, emitEvent } = await import("../core/telemetry")
          const pid = config.projectId || config.apiKey
          initTelemetry(config, pid, "nextjs")
          emitEvent(d, config)
        }
      }
        if (config.apiKey && config.telemetry !== false) {
          const { flushSync } = await import("../core/telemetry")
          await flushSync()
        }
      if (piEvents.length > 0 && config.strictMode) {
        return new Response(JSON.stringify({ error: "Prompt injection detected by Septr", details: buildBlockDetails(piEvents[0]) }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        })
      }
    }

    // Business logic tamper detection (Edge-safe: synchronous)
    if (config.tamper && ["POST", "PUT", "PATCH"].includes(request.method) && piInput) {
      try {
        const body = JSON.parse(piInput)
        if (body && typeof body === "object") {
          const tamperEvents = detectBusinessLogicTamper(body, config.fieldConstraints, request.nextUrl.pathname, request.method)
          for (const d of tamperEvents) {
            detections.push(d)
            if (config.apiKey && config.telemetry !== false) {
              const { initTelemetry, emitEvent } = await import("../core/telemetry")
              const pid = config.projectId || config.apiKey
              initTelemetry(config, pid, "nextjs")
              emitEvent(d, config)
            }
          }
        if (config.apiKey && config.telemetry !== false) {
          const { flushSync } = await import("../core/telemetry")
          await flushSync()
        }
          if (tamperEvents.length > 0 && config.strictMode) {
            return new Response(JSON.stringify({ error: "Business logic tamper detected by Septr", details: buildBlockDetails(tamperEvents[0]) }), {
              status: 400,
              headers: { "Content-Type": "application/json" },
            })
          }
        }
      } catch {
        // body not parseable
      }
    }

    // Missing auth detection (Edge-safe: header check)
    const authEvent = detectMissingAuth(
      request.nextUrl.pathname,
      request.method,
      request.headers.get("authorization") ?? undefined,
    )
    if (authEvent) {
      detections.push(authEvent)
      if (config.apiKey && config.telemetry !== false) {
        const { initTelemetry, emitEvent } = await import("../core/telemetry")
        const pid = config.projectId || config.apiKey
        initTelemetry(config, pid, "nextjs")
        emitEvent(authEvent, config)
      }
    }

    if (detections.length > 0 && config.apiKey && config.telemetry !== false) {
      const { initTelemetry, emitEvent } = await import("../core/telemetry")
      const pid = config.projectId || config.apiKey
      initTelemetry(config, pid, "nextjs")
      for (const d of detections) emitEvent(d, config)
    }

    // Edge middleware is request-scoped — the isolate can be torn down before
    // the flush interval fires, so force-flush buffered events synchronously.
    if (config.apiKey && config.telemetry !== false) {
      const { flushSync } = await import("../core/telemetry")
      await flushSync()
    }

    return
    })().catch((err) => {
      console.error("[septr] middleware error; failing open", err)
      return undefined
    })
  }
}

/** Wrap an individual Next.js API route handler with Septr protection (rate limiting, BOLA detection, response secret stripping). */
export function withSeptr(handler: (req: NextRequest) => Promise<NextResponse>, config?: SeptrConfig) {
  const normalizedConfig: SeptrConfig = {
    secrets: true,
    bola: true,
    rateLimit: true,
    inputSanitize: true,
    ssrf: true,
    promptInjection: true,
    tamper: true,
    telemetry: true,
    ...config,
  }
  const middleware = createSeptr(normalizedConfig)

  const guard = new EngineGuard({
    failureThreshold: normalizedConfig.engineFailureThreshold,
    budgetMs: normalizedConfig.engineBudgetMs,
    onDegraded: (engine, reason) => {
      emitEvent({
        type: "system",
        severity: "info",
        patternId: "engine_degraded",
        description: `Engine \`${engine}\` degraded and was disabled for this process (${reason}). Restart the app to retry, or upgrade the Septr SDK.`,
        timestamp: Date.now(),
      }, normalizedConfig)
    },
  })

  return async function protectedHandler(request: NextRequest): Promise<NextResponse> {
    if (killSwitchEngaged(normalizedConfig)) {
      return handler(request)
    }
    const result = await middleware(request)
    if (result) return result as NextResponse

    const response = await handler(request)

    // Advisory: report responses missing standard security headers.
    if (normalizedConfig.securityHeaders !== false) {
      for (const d of guard.run("security_headers", () => detectMissingSecurityHeaders(response.headers), [] as DetectionEvent[])) {
        emitEvent(d, normalizedConfig)
      }
    }

    if (normalizedConfig.secrets || normalizedConfig.aiRateLimit) {
      try {
        const contentLength = Number(response.headers.get("content-length") || 0)
        const maxInspect = normalizedConfig.maxResponseScanBytes && normalizedConfig.maxResponseScanBytes > 0
          ? normalizedConfig.maxResponseScanBytes
          : 1_000_000
        if (contentLength > maxInspect) {
          return response
        }
        const body = await (response.json as () => Promise<unknown>)()

        if (normalizedConfig.aiRateLimit) {
          const serialized = JSON.stringify(body)
          const aiEvents = hasRateLimitHint(serialized)
            ? guard.run("ai_rate_limit", () => detectAIRateLimit(serialized, request.nextUrl.pathname, request.method), [] as DetectionEvent[])
            : []
          for (const d of aiEvents) emitEvent(d, normalizedConfig)
        }

        if (!normalizedConfig.secrets) return response

        const { cleaned, detections } = guard.run("secrets", () => stripSensitiveData(body, normalizedConfig.stripFields), { cleaned: body, detections: [] as DetectionEvent[] })
        for (const d of detections) emitEvent(d, normalizedConfig)
        const newHeaders = new Headers(response.headers)
        if (detections.length > 0) {
          newHeaders.set("X-Septr-Stripped", String(detections.length))
        }
        return new Response(JSON.stringify(cleaned), {
          status: response.status,
          headers: newHeaders,
        }) as unknown as NextResponse
      } catch {
        // response body not parseable as JSON or already consumed
      }
    }

    return response
  }
}
