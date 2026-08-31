import type { DetectionEvent } from "./types"

interface PatternDef {
  pattern: RegExp
  severity: "critical" | "high" | "medium" | "low"
  patternId: string
  description: string
}

const PATTERNS: PatternDef[] = [
  {
    pattern: /429.*too many requests|rate.?limit.*reached|rate.?limit.*exceed/i,
    severity: "high",
    patternId: "ai_rate_limit_429",
    description: "AI service returned 429 Too Many Requests",
  },
  {
    pattern: /exceeded your (current )?quota|quota.*exceed/i,
    severity: "critical",
    patternId: "ai_rate_limit_quota",
    description: "AI service quota exhausted",
  },
  {
    pattern: /resource has been exhausted/i,
    severity: "critical",
    patternId: "ai_rate_limit_exhausted",
    description: "AI service resource exhausted",
  },
  {
    pattern: /x-ratelimit-remaining.*[:\s]+0/i,
    severity: "high",
    patternId: "ai_rate_limit_remaining_zero",
    description: "AI service rate limit remaining is zero",
  },
  {
    pattern: /insufficient_quota/i,
    severity: "critical",
    patternId: "ai_rate_limit_insufficient_quota",
    description: "AI service returned insufficient quota error",
  },
  {
    pattern: /rate.?limit.*exceeded/i,
    severity: "medium",
    patternId: "ai_rate_limit_generic",
    description: "AI rate limit exceeded",
  },
]

export function detectAIRateLimit(
  body: string,
  route?: string,
  method?: string,
): DetectionEvent[] {
  const events: DetectionEvent[] = []
  for (const def of PATTERNS) {
    if (def.pattern.test(body)) {
      events.push({
        type: "ai_rate_limit",
        severity: def.severity,
        patternId: def.patternId,
        description: def.description,
        route,
        method,
        timestamp: Date.now(),
      })
    }
  }
  return events
}
