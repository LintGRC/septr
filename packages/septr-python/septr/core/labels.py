"""Central lookup table mapping detection type -> OWASP, CWE, and remediation."""

DETECTION_LABELS = {
    "bola": {
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-285",
        "remediation": "Use authorization middleware that verifies the authenticated user owns the requested resource.",
    },
    "secret_exposure": {
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-798",
        "remediation": "Remove secrets from code and responses. Use environment variables or a secrets manager.",
    },
    "rate_limit": {
        "owasp": "A04:2023 - Insecure Design",
        "cwe": "CWE-799",
        "remediation": "Add rate limiting middleware with sensible limits per IP or user.",
    },
    "data_strip": {
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-200",
        "remediation": "Remove sensitive fields at the database/query layer before serialization.",
    },
    "input_sanitize": {
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79",
        "remediation": "Use parameterized queries for SQL. Use templating engines that auto-escape for XSS.",
    },
    "ssrf": {
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "cwe": "CWE-918",
        "remediation": "Validate and allowlist URLs before fetching. Block requests to internal IP ranges.",
    },
    "prompt_injection": {
        "owasp": "LLM01:2025 - Prompt Injection",
        "cwe": "CWE-840",
        "remediation": "Validate and sanitize user input before passing to LLMs.",
    },
    "missing_auth": {
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-306",
        "remediation": "Add authentication middleware to all non-public routes.",
    },
    "business_logic_tamper": {
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-840",
        "remediation": "Enforce business rules server-side. Validate all field constraints before processing.",
    },
    "cross_tenant_leak": {
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-285",
        "remediation": "Apply row-level security (RLS) policies filtered by tenant ID.",
    },
    "system": {
        "owasp": "",
        "cwe": "",
        "remediation": "",
    },
    "ai_rate_limit": {
        "owasp": "LLM08:2025 - Excessive Agency",
        "cwe": "CWE-799",
        "remediation": "Implement retry logic with exponential backoff for AI API calls. Monitor usage quotas and set up alerts before hitting rate limits.",
    },
}


def get_detection_labels(detection_type: str) -> dict:
    """Get OWASP/CWE/remediation labels for a detection type."""
    return DETECTION_LABELS.get(detection_type, {"owasp": "", "cwe": "", "remediation": ""})


def build_block_details(ev: dict) -> dict:
    """Build a full details object from a detection event."""
    labels = get_detection_labels(ev.get("type", ""))
    return {
        "type": ev.get("type", ""),
        "severity": ev.get("severity", ""),
        "location": ev.get("location", ev.get("route")),
        "pattern": ev.get("pattern", ev.get("patternId")),
        "owasp": labels["owasp"],
        "cwe": labels["cwe"],
        "description": ev.get("description", ""),
        "remediation": labels["remediation"],
    }
