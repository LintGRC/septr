import type { DetectionEvent } from "./types"

const SQLI_PATTERNS: [string, RegExp][] = [
  ["sqli_union", /(\bUNION\b(?:\s+ALL\s+)?\s*\bSELECT\b)/i],
  ["sqli_or_1_1", /(\bOR\b\s+1\s*=\s*1)/i],
  ["sqli_or_true", /(\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)/i],
  ["sqli_drop", /(\bDROP\b\s+\bTABLE\b)/i],
  ["sqli_insert", /(\bINSERT\b\s+\bINTO\b)/i],
  ["sqli_delete", /(\bDELETE\b\s+\bFROM\b)/i],
  ["sqli_alter", /(\bALTER\b\s+\bTABLE\b)/i],
  // `EXEC(` is a SQL keyword, but `regex.exec(`, `fn.exec(` is a JS/Python
  // method call — the most common false positive in Node codebases. Require a
  // non-dot boundary so method calls are not flagged.
  ["sqli_exec", /(?<!\.)\b(EXEC|EXECUTE)\s*\(/i],
  // Comment injection: `admin'--` / `x'/*` — a quote-terminated string VALUE
  // followed by a comment marker (preceding word char proves the quote ends
  // a value, not a standalone quote). Bare `--`, `/* */`, or `"--flag"` in
  // source code is a normal comment/string, NOT an injection. No newlines
  // between the quote and marker — a doc comment on the next line is code.
  ["sqli_comment", /([\w)\]])['"][ \t]*(--[^\n\r]*|\/\*[\s\S]*?\*\/)/],
  ["sqli_pg_sleep", /(\bPG_SLEEP\b\s*\()/i],
  ["sqli_waitfor", /(\bWAITFOR\b\s+\bDELAY\b)/i],
  ["sqli_benchmark", /(\bBENCHMARK\b\s*\()/i],
  ["sqli_into_outfile", /(\bINTO\b\s+\bOUTFILE\b)/i],
  ["sqli_information_schema", /(\bINFORMATION_SCHEMA\b)/i],
]

const XSS_PATTERNS: [string, RegExp][] = [
  // Tag patterns: `[\s>/]` covers both ` <script` and the slash form
  // `<script/` (no whitespace needed) used in filter-bypass payloads.
  ["xss_script_tag", /<script[\s>/]/i],
  ["xss_onerror", /\bonerror\s*=/i],
  ["xss_onload", /\bonload\s*=/i],
  ["xss_onclick", /\bonclick\s*=/i],
  ["xss_onmouseover", /\bonmouseover\s*=/i],
  ["xss_onsubmit", /\bonsubmit\s*=/i],
  ["xss_onfocus", /\bonfocus\s*=/i],
  ["xss_onblur", /\bonblur\s*=/i],
  ["xss_onchange", /\bonchange\s*=/i],
  // HTML5 event handlers (explicit names — no generic on[a-z]+= regex,
  // which would match benign words like once= / online= / only=).
  ["xss_ontoggle", /\bontoggle\s*=/i],
  ["xss_onpointerenter", /\bonpointerenter\s*=/i],
  ["xss_onpointerdown", /\bonpointerdown\s*=/i],
  ["xss_onpointermove", /\bonpointermove\s*=/i],
  ["xss_onpointerup", /\bonpointerup\s*=/i],
  ["xss_onanimationend", /\bonanimationend\s*=/i],
  ["xss_onkeydown", /\bonkeydown\s*=/i],
  ["xss_onkeyup", /\bonkeyup\s*=/i],
  ["xss_ondblclick", /\bondblclick\s*=/i],
  ["xss_oncontextmenu", /\boncontextmenu\s*=/i],
  ["xss_onmousedown", /\bonmousedown\s*=/i],
  ["xss_onmouseup", /\bonmouseup\s*=/i],
  ["xss_onwheel", /\bonwheel\s*=/i],
  ["xss_onscroll", /\bonscroll\s*=/i],
  ["xss_oninput", /\boninput\s*=/i],
  ["xss_ontouchstart", /\bontouchstart\s*=/i],
  ["xss_ondragstart", /\bondragstart\s*=/i],
  ["xss_ondrop", /\bondrop\s*=/i],
  ["xss_javascript_url", /javascript\s*:\s*['"]/i],
  ["xss_javascript_call", /javascript\s*:\s*[a-zA-Z_$][\w$]*\s*\(/i],
  ["xss_document_cookie", /document\s*\.\s*cookie/i],
  ["xss_alert", /alert\s*\(/i],
  ["xss_eval", /\beval\s*\(/i],
  ["xss_iframe", /<iframe[\s>/]/i],
  ["xss_object", /<object[\s>/]/i],
  ["xss_embed", /<embed[\s>/]/i],
  ["xss_svg_script", /<svg[\s>/][\s\S]*?<script/i],
]

// Narrow, targeted normalizations before XSS scanning — not a blanket
// decode (which would flag benign `&lt;script&gt;` in code chat):
//   - `&colon;` / `&#58;` → `:` (javascript&colon;alert() bypass form)
//   - `&#40;`/`&#x28;` → `(`, `&#41;`/`&#x29;` → `)`, `&quot;` → `"`
//   - `%0a` / `%0d` / `%09` → space (whitespace-encoded filter bypasses;
//     the framework layer decodes single-encoding, this catches the
//     double-encoded / raw-text forms)
//   - `%00` / `\x00` → "" (null-byte smearing)
const XSS_NORMALIZATIONS: [RegExp, string][] = [
  [/&colon;|&#58;/gi, ":"],
  [/&#40;|&#x28;/gi, "("],
  [/&#41;|&#x29;/gi, ")"],
  [/&quot;/gi, '"'],
  [/%0[aAdD]|%09/gi, " "],
  [/%00|\x00/g, ""],
]

function normalizeXSS(input: string): string {
  let out = input
  for (const [re, sub] of XSS_NORMALIZATIONS) out = out.replace(re, sub)
  // JS unicode escapes (\u006e → n) — attacker-shaped, never legit text.
  out = out.replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) =>
    String.fromCharCode(parseInt(h, 16)),
  )
  return out
}

export type InputThreatType = "sqli" | "xss"

/** Scan a string for SQL injection patterns (UNION, DROP, OR 1=1, comment injection, time-based blind, etc.). */
const SQL_KEYWORDS = [
  "SELECT", "UNION", "INSERT", "DELETE", "DROP", "ALTER", "UPDATE", "CREATE",
  "EXEC", "EXECUTE", "FROM", "WHERE", "TABLE", "INTO", "OUTFILE", "LOAD_FILE",
  "BENCHMARK", "PG_SLEEP", "WAITFOR", "INFORMATION_SCHEMA",
]

/** De-obfuscate common SQLi encoding tricks so pattern detectors can see the
 * underlying query: URL-encoding, /* comments *​/ , -- comments, 0x hex literals,
 * and char()/CHAR() calls. Detection-only — never modifies requests. */
export function normalizeSQLInput(text: string): string {
  if (!text) return text
  let out: string
  try {
    out = decodeURIComponent(text).replace(/\+/g, " ")
  } catch {
    out = text.replace(/\+/g, " ")
  }
  out = out.replace(/\/\*[\s\S]*?\*\//g, " ")
  out = out.replace(/--[^\n\r]*/g, " ")

  // Comments can split a keyword (SEL/**/ECT) — rejoin known SQL keywords.
  for (const kw of SQL_KEYWORDS) {
    const parts = kw.split("")
    out = out.replace(new RegExp(`\\b${parts[0]}\\s*${parts.slice(1).join("\\s*")}\\b`, "gi"), kw)
  }

  out = out.replace(/0x([0-9a-fA-F]{4,})/g, (m, hex: string) => {
    const bytes = hex.match(/../g)?.map((b) => parseInt(b, 16)) ?? []
    if (bytes.length > 0 && bytes.every((b) => b >= 32 && b < 127)) {
      return String.fromCharCode(...bytes)
    }
    return m
  })

  out = out.replace(/\b(?:char|chr)\s*\(\s*([0-9]+(?:\s*,\s*[0-9]+)*)\s*\)/gi, (m, codes: string) => {
    const chars = codes.split(",").map((c) => parseInt(c.trim(), 10))
    if (chars.every((c) => c >= 32 && c < 127)) {
      return String.fromCharCode(...chars)
    }
    return m
  })

  return out.replace(/\s+/g, " ")
}

export function detectSQLi(input: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const seen = new Set<string>()

  const scan = (text: string): void => {
    for (const [id, regex] of SQLI_PATTERNS) {
      if (seen.has(id)) continue
      const pattern = new RegExp(regex.source, "g" + regex.flags.replace(/g/g, ""))
      const match = pattern.exec(text)
      if (match !== null) {
        seen.add(id)
        events.push({
          type: "input_sanitize",
          severity: "high",
          patternId: id,
          description: `SQL injection pattern detected: ${id}`,
          statusCode: 400,
          timestamp: Date.now(),
          pattern: match[0],
        })
      }
    }
  }

  scan(input)
  const normalized = normalizeSQLInput(input)
  if (normalized !== input) scan(normalized)
  return events
}

/** Scan a string for XSS vectors (script tags, event handlers, javascript: URLs, iframe injection, etc.). */
export function detectXSS(input: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  const scan = (text: string): void => {
    for (const [id, regex] of XSS_PATTERNS) {
      const pattern = new RegExp(regex.source, "g" + regex.flags.replace(/g/g, ""))
      let match = pattern.exec(text)
      while (match !== null) {
        events.push({
          type: "input_sanitize",
          severity: "high",
          patternId: id,
          description: `XSS vector detected: ${id}`,
          statusCode: 400,
          timestamp: Date.now(),
          pattern: match[0],
        })
        match = pattern.exec(text)
      }
    }
  }
  scan(input)
  const normalized = normalizeXSS(input)
  if (normalized !== input) scan(normalized)
  return events
}

const NOSQLI_PATTERNS: [string, RegExp][] = [
  ["nosqli_ne", /\$ne\b/g],
  ["nosqli_gt", /\$gt\b/g],
  ["nosqli_gte", /\$gte\b/g],
  ["nosqli_lt", /\$lt\b/g],
  ["nosqli_lte", /\$lte\b/g],
  ["nosqli_in", /\$in\b/g],
  ["nosqli_nin", /\$nin\b/g],
  ["nosqli_where", /\$where\b/g],
  ["nosqli_exists", /\$exists\b/g],
  ["nosqli_regex", /\$regex\b/g],
  ["nosqli_all", /\$all\b/g],
  ["nosqli_mod", /\$mod\b/g],
  ["nosqli_size", /\$size\b/g],
  ["nosqli_elem_match", /\$elemMatch\b/g],
]

/** Scan a string for NoSQL injection operators ($ne, $where, $gt, …). */
export function detectNoSQLi(input: string): DetectionEvent[] {
  const events: DetectionEvent[] = []
  for (const [id, regex] of NOSQLI_PATTERNS) {
    const pattern = new RegExp(regex.source, "g")
    let match = pattern.exec(input)
    while (match !== null) {
      events.push({
        type: "input_sanitize",
        severity: "high",
        patternId: id,
        description: `NoSQL injection: ${id.replace("nosqli_", "")} operator`,
        statusCode: 400,
        timestamp: Date.now(),
      })
      match = pattern.exec(input)
    }
  }
  return events
}

/** Scan query parameter values for SQLi and XSS patterns. Accepts a record where values can be strings or arrays of strings (Express-style). */
export function sanitizeQuery(query: Record<string, string | string[]>): { block: boolean; detections: DetectionEvent[] } {
  const detections: DetectionEvent[] = []
  for (const val of Object.values(query)) {
    if (typeof val === "string") {
      detections.push(...detectSQLi(val), ...detectXSS(val), ...detectNoSQLi(val))
    } else if (Array.isArray(val)) {
      for (const item of val) {
        detections.push(...detectSQLi(item), ...detectXSS(item), ...detectNoSQLi(item))
      }
    }
  }
  return { block: detections.length > 0, detections }
}

/** Recursively scan an entire request body for SQLi and XSS patterns. Returns whether the request should be blocked and the list of detections. */
export function sanitizeInput(body: unknown): { block: boolean; detections: DetectionEvent[] } {
  const detections: DetectionEvent[] = []

  function scan(value: unknown): void {
    if (typeof value === "string") {
      const sqli = detectSQLi(value)
      const xss = detectXSS(value)
      const nosqli = detectNoSQLi(value)
      detections.push(...sqli, ...xss, ...nosqli)
    } else if (Array.isArray(value)) {
      for (const item of value) scan(item)
    } else if (value && typeof value === "object") {
      for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
        detections.push(...detectSQLi(key), ...detectXSS(key), ...detectNoSQLi(key))
        scan(val)
      }
    }
  }

  scan(body)

  return { block: detections.length > 0, detections }
}
