import { readFileSync, readdirSync, statSync } from "node:fs"
import { join, relative, sep } from "node:path"
import { detectSecrets } from "./secrets"
import { detectSQLi, detectXSS } from "./sanitize"
import { detectSSRF } from "./ssrf"
import { extractImportSpecifiers, checkHallucinatedPackages } from "./hallucinated"
import type { DetectionEvent } from "./types"

/** Directories never scanned — vendored/generated/build trees. */
const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", ".next", ".nuxt", ".output", "build",
  "__pycache__", ".venv", "venv", "vendor", ".cache", ".pytest_cache",
  ".turbo", ".nx",
])

/** Test fixture payloads are intentionally malicious strings — never report
 *  them as findings. Users can add their own entries to .septrignore. */
const DEFAULT_IGNORE_PATTERNS = [
  "**/__tests__/benchmark/**",
  "**/*-payloads.ts",
  "**/*-payloads.py",
  "**/fixtures/**",
]

function readIgnoreFile(root: string): string[] {
  try {
    return readFileSync(join(root, ".septrignore"), "utf-8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"))
  } catch {
    return []
  }
}

function globToRegExp(pattern: string): RegExp {
  let out = pattern
    .split("**").join("\u0000")
    .split("*").join("[^/]*")
    .split("\u0000").join(".*")
  out = out.replace(/\/$/, "(?:/.*)?$")
  return new RegExp(`^${out}$`)
}

function isIgnored(rel: string, patterns: string[]): boolean {
  const normalized = rel.split(sep).join("/")
  for (const raw of patterns) {
    const p = raw.startsWith("/") ? raw.slice(1) : raw
    if (globToRegExp(p).test(normalized)) return true
    if (globToRegExp(p + "/**").test(normalized)) return true
  }
  return false
}

/** Go module cache layout: parent dir `pkg` + entry `mod` at any depth —
 *  vendored dependency trees. The corpus studies showed private-key
 *  testdata under pkg/mod is pure false positives, so it is pruned the
 *  same way node_modules is. */
function isGoModCache(parentDir: string, entry: string): boolean {
  return entry === "mod" && parentDir.split(sep).pop() === "pkg"
}

const MAX_FILE_BYTES = 4 * 1024 * 1024

const TEXT_EXT = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml", ".yaml",
  ".toml", ".md", ".txt", ".html", ".htm", ".css", ".sql", ".py", ".rb",
  ".go", ".rs", ".sh", ".properties", ".cfg", ".ini", ".conf",
  ".tsbuildinfo", ".env", ".local",
])

function isTextish(name: string): boolean {
  const base = name.slice(name.lastIndexOf("."))
  if (TEXT_EXT.has(base)) return true
  return name === ".env" || name.startsWith(".env.")
}

export interface ScanFinding {
  patternId: string
  engine: string
  severity: string
  description: string
  file: string
  preview: string
  /** 1-based line number of the first match in the file, when known. */
  line?: number
}

export interface Hygiene {
  gitignoreMissing: boolean
  envCommitted: boolean
  giantFiles: string[]
  curlPipe: boolean
}

export interface ScanResult {
  files: number
  findings: ScanFinding[]
  hygiene: Hygiene
  specifiers?: string[]
  ignoredFiles: number
}

function redact(value: string): string {
  if (value.length <= 20) return "••••"
  return `${value.slice(0, 12)}…${value.length} chars`
}

function lineOf(text: string, pattern: string): number | undefined {
  let idx = text.indexOf(pattern)
  if (idx < 0) {
    // Match may come from the normalized (de-obfuscated) pass — e.g.
    // URL-encoded or comment-split payloads — so the exact string is not
    // in the raw file. Fall back to the first distinctive alphanumeric
    // token (≥ 6 chars) so the user still gets a usable line.
    const token = /[A-Za-z0-9_]{6,}/.exec(pattern)?.[0]
    if (token) {
      const lower = text.toLowerCase()
      const tokenLower = token.toLowerCase()
      const found = lower.indexOf(tokenLower)
      if (found >= 0) idx = found
    }
  }
  if (idx < 0) return undefined
  let line = 1
  for (let i = 0; i < idx; i++) {
    if (text[i] === "\n") line += 1
  }
  return line
}

function toFindings(events: DetectionEvent[], engine: string, file: string, text: string): ScanFinding[] {
  return events.map((e) => ({
    patternId: e.patternId,
    engine,
    severity: e.severity,
    description: e.description,
    file,
    preview: redact(e.pattern || e.description || ""),
    line: lineOf(text, e.pattern || ""),
  }))
}

export function scanFile(text: string, file: string): ScanFinding[] {
  const out: ScanFinding[] = []
  out.push(...toFindings(detectSecrets(text), "secrets", file, text))
  out.push(...toFindings(detectSQLi(text), "sanitize", file, text))
  out.push(...toFindings(detectXSS(text), "sanitize", file, text))
  out.push(...toFindings(detectSSRF(text), "ssrf", file, text))
  return out
}

export function scanDir(root: string, extraIgnore: string[] = []): ScanResult {
  const findings: ScanFinding[] = []
  const hygiene: Hygiene = {
    gitignoreMissing: false,
    envCommitted: false,
    giantFiles: [],
    curlPipe: false,
  }
  let files = 0
  let ignoredFiles = 0
  let rootGitignore = false
  const allSpecifiers: string[] = []
  const seenSpecs = new Set<string>()
  const ignorePatterns = [...DEFAULT_IGNORE_PATTERNS, ...readIgnoreFile(root), ...extraIgnore]

  const walk = (dir: string): void => {
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }
    for (const entry of entries) {
      const full = join(dir, entry)
      if (dir === root && entry === ".gitignore") {
        rootGitignore = true
        continue
      }
      if (entry.startsWith(".") && entry !== ".env" && !entry.startsWith(".env.")) {
        continue
      }
      let st: ReturnType<typeof statSync>
      try {
        st = statSync(full)
      } catch {
        continue
      }
      const rel = relative(root, full).split(sep).join("/")
      if (st.isDirectory()) {
        if (IGNORE_DIRS.has(entry)) continue
        if (isGoModCache(dir, entry)) continue
        if (isIgnored(rel + "/", ignorePatterns)) {
          ignoredFiles += 1
          continue
        }
        walk(full)
        continue
      }
      if (isIgnored(rel, ignorePatterns)) {
        ignoredFiles += 1
        continue
      }
      if (st.size > MAX_FILE_BYTES) {
        hygiene.giantFiles.push(rel)
        continue
      }
      if (entry === ".env" || entry.startsWith(".env.")) hygiene.envCommitted = true
      if (!isTextish(entry)) continue
      let text: string
      try {
        text = readFileSync(full, "utf-8")
      } catch {
        continue
      }
      files += 1
      if (!hygiene.curlPipe && /curl[^\n]*\|\s*(ba)?sh/i.test(text)) {
        hygiene.curlPipe = true
      }
      findings.push(...scanFile(text, rel))
      for (const spec of extractImportSpecifiers(text)) {
        if (!seenSpecs.has(spec)) {
          seenSpecs.add(spec)
          allSpecifiers.push(spec)
        }
      }
    }
  }

  walk(root)
  hygiene.gitignoreMissing = !rootGitignore
  return { files, findings, hygiene, specifiers: allSpecifiers, ignoredFiles }
}

/** Like scanDir, but also checks import specifiers against the npm registry
 *  for hallucinated packages. Returns a promise. */
export async function scanDirAsync(root: string, extraIgnore: string[] = []): Promise<ScanResult> {
  const result = scanDir(root, extraIgnore)
  const hallucinated = await checkHallucinatedPackages(result.specifiers ?? [])
  for (const f of hallucinated) {
    f.file = "(import analysis)"
    result.findings.push(f)
  }
  return result
}
