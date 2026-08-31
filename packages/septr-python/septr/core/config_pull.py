"""Live remote config: poll the Septr backend for project config (strictMode,
engine toggles, rate-limit settings) and apply it at runtime without redeploy.

The poller is a daemon thread: it fetches on startup and then every
`configPollMs` (default 60_000). If the backend is unreachable it keeps the
last-known config and retries on the next cycle. Disable with
`remoteConfig: false` in the middleware config or `SEPTR_REMOTE_CONFIG=false`
in the environment.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from typing import Dict, Optional

from .telemetry import project_id_from_key, telemetry_url_for

DEFAULT_POLL_MS = 60_000

_config_lock = threading.Lock()
_config_stop = threading.Event()


def config_pull_enabled(config: dict) -> bool:
    if config.get("remoteConfig") is False:
        return False
    if os.environ.get("SEPTR_REMOTE_CONFIG", "").strip().lower() == "false":
        return False
    if not config.get("apiKey"):
        return False
    return True


def _base_url(config: dict) -> str:
    base = telemetry_url_for(config)
    if base.endswith("/events"):
        base = base[: -len("/events")]
    return base.rstrip("/")


def fetch_project_config(config: dict) -> Optional[dict]:
    """Fetch the project's remote config. Returns None on any failure. Never raises."""
    api_key = config.get("apiKey") or os.environ.get("SEPTR_API_KEY") or os.environ.get("VS_API_KEY", "")
    pid = project_id_from_key(api_key) or config.get("projectId") or api_key
    if not pid:
        return None
    url = f"{_base_url(config)}/projects/{pid}/config"
    try:
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                return None
            body = json.loads(resp.read().decode("utf-8"))
        return body.get("config") or {}
    except Exception:
        return None


def apply_remote_config(config: dict, remote: dict) -> bool:
    """Merge remote config into the local config dict under lock.

    Only runtime-affecting keys are merged so local wiring (apiKey,
    telemetry_url, framework) is never clobbered by the server.

    `tenantAware` is deliberately NOT merged: it's local wiring that maps the
    app's tenant schema (tenantColumn / jwtClaim) and would be clobbered by the
    dashboard's boolean `tenantAware: false` toggle default.
    """
    runtime_keys = {
        "strictMode", "secrets", "bola", "rateLimit", "inputSanitize", "ssrf",
        "promptInjection", "missingAuth", "aiRateLimit", "aiEndpointShield",
        "tamperDetection", "dataStrip", "stripFields",
        "rateLimitConfig", "aiRateLimitConfig",
    }
    merged = {k: v for k, v in remote.items() if k in runtime_keys}
    if not merged:
        return False
    with _config_lock:
        config.update(merged)
    return True


def _poll_loop(config: dict, interval_ms: int) -> None:
    while not _config_stop.wait(interval_ms / 1000):
        try:
            remote = fetch_project_config(config)
            if remote is not None:
                apply_remote_config(config, remote)
        except Exception:
            pass


def start_config_polling(config: dict) -> threading.Thread:
    """Start the remote-config poller. Safe to call multiple times."""
    global _config_stop
    if not config_pull_enabled(config):
        return None  # type: ignore[return-value]

    # First fetch is synchronous so strictMode applies before traffic arrives.
    try:
        remote = fetch_project_config(config)
        if remote is not None:
            apply_remote_config(config, remote)
    except Exception:
        pass

    interval_ms = int(config.get("configPollMs") or os.environ.get("SEPTR_CONFIG_POLL_MS") or DEFAULT_POLL_MS)
    _config_stop.clear()
    t = threading.Thread(
        target=_poll_loop,
        args=(config, interval_ms),
        daemon=True,
        name="septr-config-poll",
    )
    t.start()
    return t


def stop_config_polling() -> None:
    global _config_stop
    _config_stop.set()
