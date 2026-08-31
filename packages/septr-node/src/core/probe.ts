/**
 * Probe a deployed app for exposed sensitive paths.
 *
 * The path list is distilled from the Google Hacking Database's web-app
 * categories (Files Containing Passwords, Sensitive Directories,
 * Footholds, Vulnerable Files) — the *patterns*, not the search-engine
 * dork syntax. Where the GHDB would search Google for these, we probe
 * the user's own app directly: one GET per path, content-verified, no
 * exploitation.
 */

import { readFileSync } from "fs"
import { findChecksFile } from "./resolve-checks"
import { scanFile, type ScanFinding } from "./scan"

export interface ProbePath {
  path: string
  severity: "critical" | "high" | "medium" | "low"
  description: string
  /** Content regex — a 200 only counts when the body matches (kills the
   *  200-on-everything false positive). Absent = existence counts. */
  content?: RegExp
}

interface CatalogEntry {
  path: string
  severity: "critical" | "high" | "medium" | "low"
  description: string
  content?: string
}

function loadProbePaths(): ProbePath[] {
  const raw = JSON.parse(readFileSync(findChecksFile("probe-paths.json"), "utf-8")) as CatalogEntry[]
  return raw.map((e) => ({
    path: e.path,
    severity: e.severity,
    description: e.description,
    ...(e.content ? { content: new RegExp(e.content, e.content.startsWith("^") ? "" : "i") } : {}),
  }))
}

export const PROBE_PATHS: ProbePath[] = loadProbePaths()

export interface ProbeFinding {
  patternId: string
  path: string
  status: number
  severity: string
  description: string
  preview: string
}

export interface DiscoveredEndpoint {
  path: string
  status: number
  contentType: string
}

export interface Fingerprint {
  frameworks: string[]
  server: string | null
  generator: string | null
}

export interface ProbeResult {
  requests: number
  findings: ProbeFinding[]
  engineFindings: ScanFinding[]
  fingerprint: Fingerprint
  endpoints: DiscoveredEndpoint[]
}

export interface ProbeOptions {
  timeoutMs?: number
  concurrency?: number
  maxEndpoints?: number
}

const MAX_ENDPOINTS = 30
const MAX_BODY_BYTES = 256 * 1024
const STATIC_EXT = new Set([
  ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
  ".woff", ".woff2", ".ttf", ".eot", ".map", ".txt", ".xml", ".pdf",
])

const FRAMEWORK_MARKERS: Array<[string, RegExp]> = [
  ["v0", /data-v0-/i],
  ["next", /\/_next\/|\b__NEXT_DATA__\b/i],
  ["nuxt", /\b__NUXT__\b|\/ _nuxt\/|\/_nuxt\//i],
  ["remix", /\b__remixContext\b/i],
  ["astro", /\bastro-[a-z]/i],
  ["react", /\bdata-reactroot\b|__reactFiber|__reactProps/i],
  ["vite", /\/@vite\//i],
  ["sveltekit", /\/_app\/immutable\//i],
  ["lovable", /lovable\.(com|dev)|lovable-tag|lovable-badge|content=["']Lovable/i],
  ["bolt", /bolt\.new|__bolt__/i],
  ["replit", /replit\.com|replit\.dev/i],
  ["base44", /base44\.com/i],
  ["windsurf", /windsurf\.com|windsurf\.ai/i],
]

function fingerprintFrom(headers: Headers, body: string): Fingerprint {
  const frameworks: string[] = []
  for (const [name, re] of FRAMEWORK_MARKERS) {
    if (re.test(body)) frameworks.push(name)
  }
  const server = headers.get("server") || null
  const poweredBy = headers.get("x-powered-by")
  if (poweredBy) {
    const fw = poweredBy.toLowerCase()
    if (fw.includes("express")) frameworks.push("express")
    if (fw.includes("next")) frameworks.push("next")
    if (fw.includes("fastify")) frameworks.push("fastify")
  }
  if (headers.has("x-vercel-id")) frameworks.push("vercel")
  if (headers.has("x-netlify-")) frameworks.push("netlify")
  return {
    frameworks: [...new Set(frameworks)],
    server,
    generator: headers.get("x-generator"),
  }
}

function linkTargets(base: string, html: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const m of html.matchAll(/(?:href|src)\s*=\s*["']([^"']+)["']/gi)) {
    const href = m[1]
    if (!href || href.startsWith("mailto:") || href.startsWith("tel:")) continue
    let url: URL
    try {
      url = new URL(href, base)
    } catch {
      continue
    }
    if (url.origin !== new URL(base).origin) continue
    if (url.hash) url.hash = ""
    const path = url.pathname + url.search
    const ext = path.slice(path.lastIndexOf(".")).toLowerCase()
    if (STATIC_EXT.has(ext)) continue
    if (seen.has(path)) continue
    seen.add(path)
    out.push(path)
  }
  return out
}

function normalizeBase(url: string): string {
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`
  return url.replace(/\/+$/, "")
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    return await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": "septr-scanner/0.1.0" },
    })
  } finally {
    clearTimeout(timer)
  }
}

/** Read a response body, capped so engine scanning can't balloon memory. */
async function readCapped(resp: Response, cap = MAX_BODY_BYTES): Promise<string> {
  const buf = await resp.arrayBuffer()
  const slice = buf.byteLength > cap ? buf.slice(0, cap) : buf
  return new TextDecoder().decode(slice)
}

function redactBody(body: string): string {
  // Never surface raw values: mask value-like tokens (key=value, JSON
  // string values, base64-ish blobs) before previewing.
  let out = body
    .replace(/=\s*[^\s&"']+/g, "=••••")
    .replace(/("[^"]{3,}"\s*:\s*)"[^"]+"/g, '$1"••••"')
    .replace(/[A-Za-z0-9+/]{24,}={0,2}/g, "••••")
  out = out.trim().slice(0, 120).replace(/\s+/g, " ")
  if (out.length > 0) return out
  return "(empty body)"
}

export async function probeUrl(rawBase: string, opts: ProbeOptions = {}): Promise<ProbeResult> {
  const base = normalizeBase(rawBase)
  const timeoutMs = opts.timeoutMs ?? 3000
  const concurrency = opts.concurrency ?? 2
  const maxEndpoints = opts.maxEndpoints ?? MAX_ENDPOINTS
  const findings: ProbeFinding[] = []
  const engineFindings: ScanFinding[] = []
  const endpoints: DiscoveredEndpoint[] = []
  let requests = 0
  let fingerprint: Fingerprint = { frameworks: [], server: null, generator: null }

  const checkOne = async (p: ProbePath): Promise<void> => {
    let resp: Response
    try {
      resp = await fetchWithTimeout(`${base}${p.path}`, timeoutMs)
    } catch {
      return // timeout / network error — not a finding
    }
    requests += 1
    if (resp.status !== 200) return
    let body: string
    try {
      body = await readCapped(resp)
    } catch {
      return
    }
    // MIT detection on the body — the same engine the SDK runs at runtime,
    // so CLI findings match what the middleware would catch.
    engineFindings.push(...scanFile(body, p.path))
    if (p.content && !p.content.test(body)) return
    findings.push({
      patternId: `probe_${p.path.replace(/[^a-zA-Z0-9]/g, "_").replace(/^_+|_+$/g, "").slice(0, 40)}`,
      path: p.path,
      status: resp.status,
      severity: p.severity,
      description: p.description,
      preview: redactBody(body),
    })
  }

  // ── root fetch: fingerprint + crawl seed + engine scan ──
  let rootHtml = ""
  try {
    const resp = await fetchWithTimeout(`${base}/`, timeoutMs)
    requests += 1
    if (resp.status === 200) {
      const body = await readCapped(resp)
      engineFindings.push(...scanFile(body, "/"))
      const ctype = resp.headers.get("content-type") || ""
      // fingerprint/crawl when the root is HTML — by content type, or by
      // body sniff when the server omits the header (common in minimal apps)
      if (ctype.includes("html") || /<!doctype\s+html|<html/i.test(body)) {
        rootHtml = body
        fingerprint = fingerprintFrom(resp.headers, rootHtml)
      }
    }
  } catch {
    // root unreachable — fingerprint stays empty, path checks still run
  }

  // bounded concurrency
  let i = 0
  async function worker(): Promise<void> {
    while (i < PROBE_PATHS.length) {
      const p = PROBE_PATHS[i++]
      await checkOne(p)
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, PROBE_PATHS.length) }, () => worker())
  await Promise.all(workers)

  // ── endpoint discovery: crawl same-origin links from the root page ──
  if (rootHtml) {
    const candidates = linkTargets(`${base}/`, rootHtml).filter((p) => p !== "/")
    let j = 0
    async function endpointWorker(): Promise<void> {
      while (j < Math.min(candidates.length, maxEndpoints)) {
        const path = candidates[j++]
        try {
          const resp = await fetchWithTimeout(`${base}${path}`, timeoutMs)
          requests += 1
          if (resp.status !== 404) {
            const body = await readCapped(resp)
            engineFindings.push(...scanFile(body, path))
            endpoints.push({
              path,
              status: resp.status,
              contentType: (resp.headers.get("content-type") || "unknown").split(";")[0],
            })
          }
        } catch {
          // unreachable — skip
        }
      }
    }
    const endpointWorkers = Array.from(
      { length: Math.min(concurrency, Math.min(candidates.length, maxEndpoints)) },
      () => endpointWorker(),
    )
    await Promise.all(endpointWorkers)
  }

  return { requests, findings, engineFindings, fingerprint, endpoints }
}
