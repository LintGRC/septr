import type { DetectionEvent } from "./types"

const PUBLIC_ROUTES = [
  "/auth", "/login", "/register", "/signup", "/logout",
  "/health", "/__septr_ping", "/favicon.ico",
]

const SKIP_METHODS = new Set(["OPTIONS", "HEAD"])

const STATIC_EXTENSIONS = [
  ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
  ".woff", ".woff2", ".ttf", ".map", ".webp", ".txt", ".xml",
]

export function detectMissingAuth(
  path: string,
  method: string,
  authHeader?: string,
): DetectionEvent | null {
  const normalizedPath = path.toLowerCase()

  if (SKIP_METHODS.has(method.toUpperCase())) return null

  if (STATIC_EXTENSIONS.some((ext) => normalizedPath.endsWith(ext))) return null

  if (PUBLIC_ROUTES.some((r) => normalizedPath.startsWith(r))) return null

  if (authHeader && /^Bearer\s+/i.test(authHeader)) return null

  return {
    type: "missing_auth",
    severity: "high",
    patternId: "missing-auth-no-header",
    description: `Route ${method} ${path} has no authentication — add middleware or a per-route auth guard`,
    route: path,
    method,
    timestamp: Date.now(),
  }
}
