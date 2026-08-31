import math
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class DetectionEvent:
    type: str = ""
    severity: str = ""
    patternId: str = ""
    description: str = ""
    route: Optional[str] = None
    method: Optional[str] = None
    statusCode: Optional[int] = None
    redactable: Optional[bool] = None
    timestamp: float = 0.0
    location: Optional[str] = None
    pattern: Optional[str] = None
    count: Optional[int] = None


def _base64url_decode(text: str) -> str:
    import base64
    b64 = text.replace("-", "+").replace("_", "/")
    padded = b64 + "=" * ((4 - len(b64) % 4) % 4)
    return base64.b64decode(padded).decode("utf-8", errors="replace")


def _jwt_has_role_factory(role: str) -> Callable[[str], bool]:
    def check(token: str) -> bool:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False
            import json
            data = json.loads(_base64url_decode(parts[1]))
        except Exception:
            return False
        return isinstance(data, dict) and data.get("role") == role
    return check


_SUPABASE_ANON_CHECK = _jwt_has_role_factory("anon")


def _not_supabase_anon(token: str) -> bool:
    return not _SUPABASE_ANON_CHECK(token)


_PUBLISHABLE_PREFIXES = ("pk_live_", "pk_test_", "pk_prod_", "pk.", "phc_", "phx_")


def _is_publishable_key(value: str) -> bool:
    return any(value.startswith(p) for p in _PUBLISHABLE_PREFIXES)


def _aws_secret_like(text: str) -> bool:
    """AWS secret access keys are 40 chars of random base64 (A-Za-z0-9+/),
    so they contain mixed character classes. Rejects path-like strings
    (e.g. "policies/risks/assets/vendors/incidents/") that are all lowercase
    or dominated by one class."""
    if len(text) != 40:
        return False
    upper = sum(1 for c in text if c.isupper())
    lower = sum(1 for c in text if c.islower())
    digits = sum(1 for c in text if c.isdigit())
    return upper >= 4 and lower >= 4 and digits >= 1


# (id, regex, description, severity, verify?, redactable) — verify receives the raw match
# and must return True to keep the detection (e.g. JWT role checks).
# redactable=False means the value is a known public key and should NOT be redacted.
SECRET_PATTERNS: list[tuple[str, re.Pattern, str, str, Optional[Callable[[str], bool]], bool]] = [
    ("openai", re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"), "OpenAI API key", "high", None, True),
    ("openai_legacy", re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"), "OpenAI legacy key", "high", None, True),
    ("openai_svc", re.compile(r"sk-svcacct-[A-Za-z0-9_-]{20,}"), "OpenAI service account key", "high", None, True),
    ("openai_admin", re.compile(r"sk-admin-[A-Za-z0-9_-]{20,}"), "OpenAI admin key", "critical", None, True),
    ("anthropic", re.compile(r"sk-ant-api03-[A-Za-z0-9_-]{20,}"), "Anthropic API key", "high", None, True),
    ("stripe_live", re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "Stripe live secret key", "high", None, True),
    ("stripe_test", re.compile(r"sk_test_[A-Za-z0-9]{20,}"), "Stripe test secret key", "medium", None, True),
    ("stripe_restricted", re.compile(r"rk_live_[A-Za-z0-9]{20,}"), "Stripe restricted key", "high", None, True),
    ("aws_access", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID", "high", None, True),
    ("aws_session", re.compile(r"ASIA[0-9A-Z]{16}"), "AWS session token key ID", "high", None, True),
    ("aws_secret", re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])"), "AWS secret access key", "high", _aws_secret_like, True),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token", "high", None, True),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "GitHub fine-grained token", "high", None, True),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth token", "high", None, True),
    ("github_app", re.compile(r"(?:ghu|ghs)_[A-Za-z0-9]{36}"), "GitHub app token", "high", None, True),
    ("slack_bot", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"), "Slack bot token", "high", None, True),
    ("slack_user", re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}"), "Slack user token", "high", None, True),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}"), "Slack webhook URL", "high", None, True),
    ("google_api", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key", "low", None, False),
    ("google_client_secret", re.compile(r"GOCSPX-[A-Za-z0-9_-]{20,}"), "Google OAuth client secret", "high", None, True),
    ("sendgrid", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "SendGrid API key", "high", None, True),
    ("twilio", re.compile(r"SK[0-9a-fA-F]{32}"), "Twilio API key", "high", None, True),
    ("shopify", re.compile(r"sh(?:pat|pss)_[0-9a-fA-F]{32}"), "Shopify access token", "high", None, True),
    ("mailchimp", re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"), "Mailchimp API key", "medium", None, True),
    ("discord_bot", re.compile(r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"), "Discord bot token", "high", None, True),
    ("azure_storage", re.compile(r"AccountKey=[A-Za-z0-9+/=]{88}"), "Azure Storage account key", "high", None, True),
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{36}"), "npm access token", "high", None, True),
    ("supabase_service_role", re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
     "Supabase service_role key", "critical", _jwt_has_role_factory("service_role"), True),
    ("supabase_anon", re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
     "Supabase anon key (public)", "low", _jwt_has_role_factory("anon"), False),
    ("generic_jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
     "JWT token", "medium", _not_supabase_anon, True),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----"), "Private key", "critical", None, True),
    ("database_uri", re.compile(r"(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s]+:[^\s]+@[^\s]+"), "Database URI with credentials", "high", None, True),
]


DEFAULT_SENSITIVE_KEYS = [
    "password", "password_hash", "passwordHash", "secret", "secret_key", "secretKey",
    "api_key", "apiKey", "private_key", "privateKey", "stripe_secret", "stripeSecret",
    "ssn", "credit_card", "creditCard", "token", "access_token", "accessToken",
    "refresh_token", "refreshToken", "authorization",
]

# ── keyword + entropy detection (advisory) ──

_ENTROPY_ASSIGN_RE = re.compile(
    r"""(?:["']?(?:apiKey|api_key|apiSecret|api_secret|secret|secretKey|secret_key|clientSecret|client_secret|token|accessToken|access_token|refreshToken|refresh_token|password|privateKey|private_key|bearerToken|authToken)["']?)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']"""
)
_ENTROPY_THRESHOLD = 3.5

_LOWER = frozenset("abcdefghijklmnopqrstuvwxyz")
_UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGIT = frozenset("0123456789")
_SYMBOL = frozenset("+/=_-.")


def _char_classes(value: str) -> int:
    classes = 0
    if any(c in _LOWER for c in value):
        classes += 1
    if any(c in _UPPER for c in value):
        classes += 1
    if any(c in _DIGIT for c in value):
        classes += 1
    if any(c in _SYMBOL for c in value):
        classes += 1
    return classes


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for c in value:
        counts[c] = counts.get(c, 0) + 1
    n = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _matches_specific_pattern(value: str) -> bool:
    for _, regex, _, _, _, _ in SECRET_PATTERNS:
        if regex.search(value):
            return True
    return False


def detect_high_entropy_secrets(text: str) -> list[DetectionEvent]:
    """Advisory detection: high-entropy values assigned to secret-like keys.

    Never used for redaction — only for telemetry events. Values already
    matched by a specific pattern are skipped.
    """
    events: list[DetectionEvent] = []
    for m in _ENTROPY_ASSIGN_RE.finditer(text):
        value = m.group(1)
        if len(value) > 128:
            continue
        if _char_classes(value) < 3:
            continue
        # Pure hex / hex-dash values are IDs, hashes, and UUIDs — not secrets.
        if re.fullmatch(r"[0-9a-fA-F\-]+", value):
            continue
        if _matches_specific_pattern(value):
            continue
        if _is_publishable_key(value):
            continue
        if _shannon_entropy(value) < _ENTROPY_THRESHOLD:
            continue
        events.append(DetectionEvent(
            type="secret_exposure", severity="medium",
            patternId="secret_high_entropy",
            description="High-entropy value assigned to a secret-like key (possible API key or token)",
            statusCode=200, timestamp=time.time() * 1000,
        ))
    return events


def detect_secrets(text: str, custom_patterns: Optional[list[str]] = None) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    for pattern_id, regex, description, severity, verify, redactable in SECRET_PATTERNS:
        for m in regex.finditer(text):
            if verify and not verify(m.group(0)):
                continue
            events.append(DetectionEvent(
                type="secret_exposure", severity=severity,
                patternId=f"secret_{pattern_id}", description=description,
                redactable=False if not redactable else None,
                statusCode=200, timestamp=time.time() * 1000,
            ))
    if custom_patterns:
        for pattern_str in custom_patterns:
            try:
                regex = re.compile(pattern_str)
                for _ in regex.finditer(text):
                    events.append(DetectionEvent(
                        type="secret_exposure", severity="high",
                        patternId="secret_custom", description="Custom pattern match detected",
                        statusCode=200, timestamp=time.time() * 1000,
                    ))
            except re.error:
                pass
    return events


def should_strip_key(key: str, custom_fields: Optional[list[str]] = None) -> bool:
    if not key:
        return False
    normalized = key.lower().replace("_", "").replace("-", "")
    sensitive = custom_fields if custom_fields is not None else DEFAULT_SENSITIVE_KEYS
    for field in sensitive:
        normalized_field = field.lower().replace("_", "").replace("-", "")
        if normalized == normalized_field:
            return True
    return False
