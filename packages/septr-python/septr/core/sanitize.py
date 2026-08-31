import re
import time
import urllib.parse
from .secrets import DetectionEvent


SQLI_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sqli_union", re.compile(r"(\bUNION\b\s+\bSELECT\b)", re.I)),
    ("sqli_or_1_1", re.compile(r"(\bOR\b\s+1\s*=\s*1)", re.I)),
    ("sqli_or_true", re.compile(r"(\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)", re.I)),
    ("sqli_drop", re.compile(r"(\bDROP\b\s+\bTABLE\b)", re.I)),
    ("sqli_insert", re.compile(r"(\bINSERT\b\s+\bINTO\b)", re.I)),
    ("sqli_delete", re.compile(r"(\bDELETE\b\s+\bFROM\b)", re.I)),
    ("sqli_alter", re.compile(r"(\bALTER\b\s+\bTABLE\b)", re.I)),
    ("sqli_exec", re.compile(r"(\bEXEC\b|\bEXECUTE\b)\s*\(", re.I)),
    ("sqli_comment", re.compile(r"--\s*$|/\*[\s\S]*?\*/", re.M)),
    ("sqli_pg_sleep", re.compile(r"(\bPG_SLEEP\b\s*\()", re.I)),
    ("sqli_waitfor", re.compile(r"(\bWAITFOR\b\s+\bDELAY\b)", re.I)),
    ("sqli_benchmark", re.compile(r"(\bBENCHMARK\b\s*\()", re.I)),
    ("sqli_into_outfile", re.compile(r"(\bINTO\b\s+\bOUTFILE\b)", re.I)),
    ("sqli_information_schema", re.compile(r"(\bINFORMATION_SCHEMA\b)", re.I)),
]

XSS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("xss_script_tag", re.compile(r"<script[\s>]", re.I)),
    ("xss_onerror", re.compile(r"\bonerror\s*=", re.I)),
    ("xss_onload", re.compile(r"\bonload\s*=", re.I)),
    ("xss_onclick", re.compile(r"\bonclick\s*=", re.I)),
    ("xss_onmouseover", re.compile(r"\bonmouseover\s*=", re.I)),
    ("xss_onsubmit", re.compile(r"\bonsubmit\s*=", re.I)),
    ("xss_onfocus", re.compile(r"\bonfocus\s*=", re.I)),
    ("xss_onblur", re.compile(r"\bonblur\s*=", re.I)),
    ("xss_onchange", re.compile(r"\bonchange\s*=", re.I)),
    ("xss_javascript_url", re.compile(r"javascript\s*:\s*['\"]", re.I)),
    ("xss_document_cookie", re.compile(r"document\s*\.\s*cookie", re.I)),
    ("xss_alert", re.compile(r"alert\s*\(", re.I)),
    ("xss_eval", re.compile(r"\beval\s*\(", re.I)),
    ("xss_iframe", re.compile(r"<iframe[\s>]", re.I)),
    ("xss_object", re.compile(r"<object[\s>]", re.I)),
    ("xss_embed", re.compile(r"<embed[\s>]", re.I)),
    ("xss_svg_script", re.compile(r"<svg[\s>][\s\S]*?<script", re.I)),
]


def normalize_sql_input(text: str) -> str:
    """De-obfuscate common SQLi encoding tricks so pattern detectors can see
    the underlying query: URL-encoding, /* comments */, -- comments, 0x hex
    literals, and char()/CHAR() calls. Detection-only — never modifies requests."""
    if not text:
        return text
    text = urllib.parse.unquote(text)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"--[^\n\r]*", " ", text)

    # Comments can split a keyword (SEL/**/ECT). After removal they leave a
    # space — rejoin known SQL keywords so detectors see the real query.
    for kw in ("SELECT", "UNION", "INSERT", "DELETE", "DROP", "ALTER",
               "UPDATE", "CREATE", "EXEC", "EXECUTE", "FROM", "WHERE",
               "TABLE", "INTO", "OUTFILE", "LOAD_FILE", "BENCHMARK",
               "PG_SLEEP", "WAITFOR", "INFORMATION_SCHEMA"):
        text = re.sub(rf"\b{kw[0]}\s*" + r"\s*".join(kw[1:]) + r"\b", kw, text, flags=re.I)

    def hex_replace(m: re.Match) -> str:
        try:
            raw = bytes.fromhex(m.group(1))
            if all(32 <= b < 127 for b in raw):
                return raw.decode("ascii")
        except ValueError:
            pass
        return m.group(0)

    text = re.sub(r"0x([0-9a-fA-F]{4,})", hex_replace, text)

    def char_replace(m: re.Match) -> str:
        try:
            codes = [int(c) for c in m.group(1).split(",")]
            return "".join(chr(c) for c in codes if 32 <= c < 127)
        except ValueError:
            return m.group(0)

    text = re.sub(
        r"\b(?:char|chr)\s*\(\s*([0-9]+(?:\s*,\s*[0-9]+)*)\s*\)",
        char_replace, text, flags=re.I,
    )
    return re.sub(r"\s+", " ", text)


def detect_sqli(text: str) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    seen: set[str] = set()

    def scan(t: str) -> None:
        for pattern_id, regex in SQLI_PATTERNS:
            if pattern_id in seen:
                continue
            if regex.search(t):
                seen.add(pattern_id)
                events.append(DetectionEvent(
                    type="input_sanitize", severity="high",
                    patternId=pattern_id, description=f"SQLi pattern: {pattern_id}",
                    statusCode=400,
                    timestamp=time.time() * 1000,
                ))

    scan(text)
    normalized = normalize_sql_input(text)
    if normalized != text:
        scan(normalized)
    return events


def detect_xss(text: str) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    for pattern_id, regex in XSS_PATTERNS:
        for _ in regex.finditer(text):
            events.append(DetectionEvent(
                type="input_sanitize", severity="medium",
                patternId=pattern_id, description=f"XSS pattern: {pattern_id}",
                statusCode=400,
                timestamp=time.time() * 1000,
            ))
    return events


def sanitize_query(query: dict[str, str | list[str]]) -> tuple[bool, list[DetectionEvent]]:
    detections: list[DetectionEvent] = []
    for key, value in query.items():
        if isinstance(value, str):
            detections.extend(sanitize_string(value))
        elif isinstance(value, list):
            for v in value:
                detections.extend(sanitize_string(v))
    return len(detections) > 0, detections


def sanitize_input(body: object, depth: int = 0) -> tuple[bool, list[DetectionEvent]]:
    if depth > 10:
        return False, []
    detections: list[DetectionEvent] = []
    if isinstance(body, str):
        detections.extend(sanitize_string(body))
    elif isinstance(body, dict):
        for key, value in body.items():
            detections.extend(sanitize_string(key))
            if isinstance(value, (str, dict, list)):
                _, sub = sanitize_input(value, depth + 1)
                detections.extend(sub)
    elif isinstance(body, list):
        for item in body:
            _, sub = sanitize_input(item, depth + 1)
            detections.extend(sub)
    return len(detections) > 0, detections


NOSQLI_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("nosqli_ne", re.compile(r"\$ne\b")),
    ("nosqli_gt", re.compile(r"\$gt\b")),
    ("nosqli_gte", re.compile(r"\$gte\b")),
    ("nosqli_lt", re.compile(r"\$lt\b")),
    ("nosqli_lte", re.compile(r"\$lte\b")),
    ("nosqli_in", re.compile(r"\$in\b")),
    ("nosqli_nin", re.compile(r"\$nin\b")),
    ("nosqli_where", re.compile(r"\$where\b")),
    ("nosqli_exists", re.compile(r"\$exists\b")),
    ("nosqli_regex", re.compile(r"\$regex\b")),
    ("nosqli_all", re.compile(r"\$all\b")),
    ("nosqli_mod", re.compile(r"\$mod\b")),
    ("nosqli_size", re.compile(r"\$size\b")),
    ("nosqli_elem_match", re.compile(r"\$elemMatch\b")),
]


def detect_nosqli(text: str) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    for pattern_id, regex in NOSQLI_PATTERNS:
        for _ in regex.finditer(text):
            events.append(DetectionEvent(
                type="input_sanitize", severity="high",
                patternId=pattern_id,
                description=f"NoSQL injection: {pattern_id.removeprefix('nosqli_')} operator",
                statusCode=400,
                timestamp=time.time() * 1000,
            ))
    return events


def sanitize_string(text: str) -> list[DetectionEvent]:
    return detect_sqli(text) + detect_xss(text) + detect_nosqli(text)
