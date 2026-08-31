/**
 * Live remote config: poll the Septr backend for the project config
 * (strictMode, engine toggles, rate-limit settings) and apply it to the
 * running middleware without redeploying.
 *
 * Polls on startup and then every `configPollMs` (default 60_000). On
 * backend failure the last-known config is kept and the next cycle retries.
 * Disable with `remoteConfig: false` in the config or
 * `SEPTR_REMOTE_CONFIG=false` in the environment.
 */

import type { SeptrConfig } from "./types"

const DEFAULT_POLL_MS = 60_000

const RUNTIME_KEYS = new Set<string>([
  "strictMode", "secrets", "bola", "rateLimit", "inputSanitize", "ssrf",
  "promptInjection", "missingAuth", "aiRateLimit", "aiEndpointShield",
  "tamper", "tenantAware", "stripFields", "rateLimitConfig", "aiRateLimitConfig",
])

export function configPullEnabled(config: SeptrConfig): boolean {
  if (config.remoteConfig === false) return false
  if (
    typeof process !== "undefined" &&
    process.env?.SEPTR_REMOTE_CONFIG?.trim().toLowerCase() === "false"
  ) {
    return false
  }
  return Boolean(config.apiKey)
}

function baseUrl(config: SeptrConfig): string {
  const url = (config.telemetryUrl as string) || "https://api.septr.com/v1/events"
  return url.endsWith("/events") ? url.slice(0, -"/events".length) : url
}

function projectIdFromKey(apiKey: string): string | null {
  const m = /^septr_live_([0-9a-fA-F-]{36})_[0-9a-f]{32}$/.exec(apiKey)
  return m ? m[1] : null
}

export async function fetchProjectConfig(
  config: SeptrConfig,
): Promise<SeptrConfig | null> {
  const apiKey = (config.apiKey as string) || ""
  const pid = projectIdFromKey(apiKey) || (config.projectId as string) || apiKey
  if (!pid || typeof fetch !== "function") return null
  const url = `${baseUrl(config)}/projects/${encodeURIComponent(pid)}/config`
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(5_000),
    })
    if (!response.ok) return null
    const body = (await response.json()) as { config?: SeptrConfig }
    return body.config ?? null
  } catch {
    return null
  }
}

export function applyRemoteConfig(
  config: SeptrConfig,
  remote: SeptrConfig,
): boolean {
  const target = config as Record<string, unknown>
  let changed = false
  for (const [key, value] of Object.entries(remote)) {
    if (RUNTIME_KEYS.has(key)) {
      target[key] = value
      changed = true
    }
  }
  return changed
}

let pollTimer: ReturnType<typeof setInterval> | null = null

export function stopConfigPolling(): void {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

export async function startConfigPolling(
  config: SeptrConfig,
): Promise<void> {
  if (!configPullEnabled(config)) return

  // First fetch is awaited so strictMode applies before traffic arrives.
  const first = await fetchProjectConfig(config)
  if (first) applyRemoteConfig(config, first)

  if (pollTimer) clearInterval(pollTimer)
  const intervalMs = Number(config.configPollMs)
    || Number(process.env?.SEPTR_CONFIG_POLL_MS)
    || DEFAULT_POLL_MS
  pollTimer = setInterval(() => {
    fetchProjectConfig(config).then((remote) => {
      if (remote) applyRemoteConfig(config, remote)
    })
  }, intervalMs)
  if (typeof pollTimer.unref === "function") pollTimer.unref()
}
