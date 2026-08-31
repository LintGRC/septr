import type { ScanFinding } from "./scan"

const NPM_REGISTRY_URL = "https://registry.npmjs.org"
const REGISTRY_TIMEOUT = 8_000
const MAX_PACKAGES_PER_SCAN = 60
const MAX_CONCURRENT = 6

const NODE_BUILTINS = new Set([
  "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
  "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
  "events", "fs", "http", "http2", "https", "inspector", "module", "net",
  "os", "path", "perf_hooks", "process", "punycode", "querystring",
  "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
  "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads",
  "zlib",
])

const NON_BARE_PREFIXES = ["node:", "bun:", "deno:", "jsr:", "virtual:", "vite:"]
const ASSET_SUFFIXES = new Set([
  ".css", ".scss", ".sass", ".less", ".svg", ".png", ".jpg", ".jpeg",
  ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".map",
  ".json", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx",
  ".vue", ".svelte", ".wasm",
])

const IMPORT_RE = /\b(?:import|export)\s+.*?\s+from\s+["']([^"']+)["']/g
const REQUIRE_RE = /(?<![\w.$])require\(\s*["']([^"']+)["']\s*\)/g
const NAME_RE = /^@?[A-Za-z0-9._~-]+(\/@?[A-Za-z0-9._~-]+)?$/

// In-process cache: package name -> exists on npm
const existsCache = new Map<string, boolean>()
// Scope cache: scope name -> has public packages
const scopeCache = new Map<string, boolean>()

function stripSpecifier(spec: string): string | null {
  let s = spec.split("?")[0].split("#")[0].trim()
  if (!s) return null
  if (s.startsWith(".") || s.startsWith("/") || s.startsWith("file:") || s.startsWith("http:") || s.startsWith("https:")) return null
  if (NON_BARE_PREFIXES.some((p) => s.startsWith(p))) return null
  if (ASSET_SUFFIXES.has(s.slice(s.lastIndexOf(".")))) return null
  if (NODE_BUILTINS.has(s)) return null
  const parts = s.split("/")
  if (parts.length === 1) {
    // unscoped — ok
  } else if (parts.length === 2 && parts[0].startsWith("@")) {
    // scoped — ok
  } else {
    return null
  }
  if (!NAME_RE.test(s)) return null
  return s
}

function insideTryCatch(text: string, pos: number): boolean {
  const back = text.slice(Math.max(0, pos - 300), pos)
  const idx = back.lastIndexOf("try")
  if (idx === -1) return false
  const seg = back.slice(idx + 3).trimStart()
  if (!seg.startsWith("{")) return false
  if (seg.includes("}")) return false
  const fwd = text.slice(pos, pos + 300)
  return /}\s*(?:catch|finally)/.test(fwd)
}

/** Extract bare npm package names from JS/TS/HTML text. */
export function extractImportSpecifiers(text: string): string[] {
  const names: string[] = []
  const seen = new Set<string>()

  const add = (name: string | null): void => {
    if (name && !seen.has(name)) {
      seen.add(name)
      names.push(name)
    }
  }

  let m: RegExpExecArray | null
  IMPORT_RE.lastIndex = 0
  while ((m = IMPORT_RE.exec(text)) !== null) {
    add(stripSpecifier(m[1]))
  }

  REQUIRE_RE.lastIndex = 0
  while ((m = REQUIRE_RE.exec(text)) !== null) {
    if (!insideTryCatch(text, m.index)) {
      add(stripSpecifier(m[1]))
    }
  }

  return names
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    return await fetch(url, {
      signal: ctrl.signal,
      headers: { "User-Agent": "septr/0.1.0" },
    })
  } finally {
    clearTimeout(timer)
  }
}

/** True if the package exists on npm (or we can't tell). Never throws. */
async function registryExists(name: string): Promise<boolean> {
  const cached = existsCache.get(name)
  if (cached !== undefined) return cached

  let exists = true
  try {
    const encoded = encodeURIComponent(name)
    const resp = await fetchWithTimeout(`${NPM_REGISTRY_URL}/${encoded}`, REGISTRY_TIMEOUT)
    exists = resp.status < 400
  } catch {
    exists = true // fail-safe: transient errors never flag a package
  }
  existsCache.set(name, exists)
  return exists
}

/** True if the scope has public packages on npm. Fail-safe: errors = exists. */
async function scopeExists(scope: string): Promise<boolean> {
  if (!scope.startsWith("@")) return true
  const cached = scopeCache.get(scope)
  if (cached !== undefined) return cached

  let exists = true
  try {
    const resp = await fetchWithTimeout(
      `${NPM_REGISTRY_URL}/-/v1/search?text=scope:${encodeURIComponent(scope)}&size=20`,
      REGISTRY_TIMEOUT,
    )
    if (resp.status < 400) {
      const data = await resp.json() as { objects?: Array<{ package?: { name?: string } }> }
      const prefix = `${scope}/`
      exists = (data.objects ?? []).some((obj) => obj.package?.name?.startsWith(prefix))
    }
  } catch {
    exists = true
  }
  scopeCache.set(scope, exists)
  return exists
}

/** Run async tasks with bounded concurrency. */
async function parallel<T>(items: T[], fn: (item: T) => Promise<boolean>, limit: number): Promise<boolean[]> {
  const results: boolean[] = new Array(items.length)
  let i = 0
  async function worker(): Promise<void> {
    while (i < items.length) {
      const idx = i++
      results[idx] = await fn(items[idx])
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()))
  return results
}

/** Check collected import specifiers against the npm registry.
 *  Returns ScanFinding[] for packages confirmed missing (HTTP 404). */
export async function checkHallucinatedPackages(specifiers: string[]): Promise<ScanFinding[]> {
  const candidates = specifiers.slice(0, MAX_PACKAGES_PER_SCAN)
  if (candidates.length === 0) return []

  const existsResults = await parallel(candidates, registryExists, MAX_CONCURRENT)

  const findings: ScanFinding[] = []
  for (let i = 0; i < candidates.length; i++) {
    if (existsResults[i]) continue
    const name = candidates[i]
    const scope = name.split("/")[0]
    if (name.startsWith("@") && !(await scopeExists(scope))) continue
    findings.push({
      patternId: "hallucinated_package",
      engine: "hallucinated",
      severity: "high",
      description: `Package does not exist on npm: ${name}`,
      file: "",
      preview: name,
    })
  }
  return findings
}

/** Reset caches (for testing). */
export function clearHallucinatedCache(): void {
  existsCache.clear()
  scopeCache.clear()
}
