"""Fail-loud diagnostics for SEPTR_* environment configuration.

Detects the classic "wrong key inherited" footgun: a ``SEPTR_API_KEY`` exported
by the shell or a launch script overrides the app's own ``.env`` file (python-
dotenv defaults to ``override=False``, so the inherited value wins). When that
happens telemetry lands in the wrong project with no error anywhere.

Best-effort discovery: ``.env`` files are looked up near the process working
directory (``cwd/.env``, the parent's ``.env``, and one level of ``cwd``
children). Apps that load ``.env`` files elsewhere (e.g. behind a monorepo
launcher) may not be covered — the handshake log line still names the
connected project, so misrouting stays visible.
"""

import os
import re
import sys
from pathlib import Path
from typing import Optional

_warned = False

_SILENCE_VALUES = ("1", "true", "yes")

_KEY_RE = re.compile(r"^(septr_live_|vs_live_)([0-9a-fA-F-]{36})_([0-9a-fA-F]{32})$")


def mask_key(key: str) -> str:
    """Mask an API key for display, keeping the embedded project id visible
    (the id is what identifies the *wrong* project in a misrouting scenario)."""
    m = _KEY_RE.match(key)
    if m:
        prefix, pid, secret = m.groups()
        return f"{prefix}{pid[:4]}…{pid[-4:]}_{secret[:2]}…{secret[-4:]}"
    if len(key) <= 12:
        return "***"
    return f"{key[:8]}…{key[-4:]}"


def read_dotenv_key(path: Path, key_name: str) -> Optional[str]:
    """Best-effort parse of ``KEY=VALUE`` from a .env file (no deps)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        k, _, v = stripped.partition("=")
        if k.strip() != key_name:
            continue
        v = v.strip()
        if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
            v = v[1:-1]
        return v
    return None


def env_dotenv_candidates(cwd: Optional[Path] = None) -> list[Path]:
    """Likely locations for the app's .env file, nearest first."""
    cwd = cwd or Path.cwd()
    candidates = [cwd / ".env", cwd.parent / ".env"]
    try:
        for child in cwd.iterdir():
            if child.is_dir():
                candidates.append(child / ".env")
    except OSError:
        pass
    return candidates


def check_env_vs_dotenv(
    env_key: str,
    key_name: str = "SEPTR_API_KEY",
    candidates: Optional[list[Path]] = None,
) -> list[str]:
    """Return warning lines when the process env key differs from the key in a
    discovered local .env file. Fires at most once per process."""
    global _warned
    if _warned or not env_key:
        return []
    if os.environ.get("SEPTR_SILENCE_ENV_WARNING", "").strip().lower() in _SILENCE_VALUES:
        return []
    for path in candidates or env_dotenv_candidates():
        local_key = read_dotenv_key(path, key_name)
        if local_key and local_key != env_key:
            _warned = True
            return [(
                f"⚠️  [septr] WARNING: the {key_name} in this process environment "
                f"({mask_key(env_key)}) does not match the one in {path} "
                f"({mask_key(local_key)}). Telemetry may be routing to the wrong "
                f"project. Check for {key_name} exported by your shell or launch "
                f"script — it overrides the app's .env file."
            )]
    return []


def warn_env_vs_dotenv(env_key: str, candidates: Optional[list[Path]] = None) -> None:
    """Print the env-vs-.env mismatch warning to stderr (once)."""
    for line in check_env_vs_dotenv(env_key, candidates=candidates):
        print(line, file=sys.stderr, flush=True)
