import json
import os
import re
import sys
import time
import threading
import urllib.request
from typing import Optional
from .env_check import warn_env_vs_dotenv
from .secrets import DetectionEvent


DEFAULT_FLUSH_INTERVAL_MS = 30000
MAX_BATCH_SIZE = 50
MAX_BUFFER_SIZE = 500
MAX_RETRY_INTERVAL_MS = 300000

DEFAULT_HEARTBEAT_INTERVAL_MS = 60000


def heartbeat_interval_ms() -> int:
    """Heartbeat cadence from env (SEPTR_HEARTBEAT_INTERVAL_MS); 0 disables."""
    raw = (
        os.environ.get("SEPTR_HEARTBEAT_INTERVAL_MS")
        or os.environ.get("VS_HEARTBEAT_INTERVAL_MS")
        or ""
    )
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_HEARTBEAT_INTERVAL_MS

_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LONG_NUMERIC = re.compile(r"\d{5,}")

_V2_KEY_PATTERN = re.compile(r"^septr_live_([0-9a-fA-F-]{36})_([0-9a-f]{32})$")


def _package_version() -> str:
    """Resolve the installed septr version; falls back to 0.1.0."""
    try:
        from importlib.metadata import version
        return version("septr")
    except Exception:
        return "0.1.0"


def _redact_path(path: str) -> str:
    if not path:
        return path
    result = _EMAIL_PATTERN.sub(":email", path)
    result = _UUID_PATTERN.sub(":id", result)
    result = _IPV4_PATTERN.sub(":ip", result)
    result = _LONG_NUMERIC.sub(":id", result)
    return result


def project_id_from_key(api_key: str) -> Optional[str]:
    """Extract the embedded project id from a structured v2 key, if present."""
    if not api_key:
        return None
    m = _V2_KEY_PATTERN.match(api_key)
    if not m:
        return None
    try:
        from uuid import UUID
        return str(UUID(m.group(1)))
    except ValueError:
        return None


def telemetry_url_for(config: dict) -> str:
    """Resolve the telemetry endpoint from config, then env, then default."""
    return (
        config.get("telemetry_url")
        or config.get("telemetryUrl")
        or os.environ.get("SEPTR_TELEMETRY_URL")
        or os.environ.get("VS_TELEMETRY_URL")
        or "https://api.septr.com/v1/events"
    )


class TelemetryManager:
    def __init__(self, config: dict, project_id: str):
        self.config = config
        self.project_id = project_id
        self.buffer: list[DetectionEvent] = []
        self.destroyed = False
        self.current_flush_interval = DEFAULT_FLUSH_INTERVAL_MS
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._latency_samples: list[float] = []
        self._latency_lock = threading.Lock()
        self._heartbeat_timer: Optional[threading.Timer] = None
        self._route_inventory: dict[tuple[str, str, str], int] = {}
        self._schedule_flush()
        self._schedule_heartbeat()

    def _schedule_flush(self):
        if self.destroyed or self.current_flush_interval <= 0:
            return
        self._timer = threading.Timer(self.current_flush_interval / 1000, self._flush)
        self._timer.daemon = True
        self._timer.start()

    def _schedule_heartbeat(self):
        interval_ms = heartbeat_interval_ms()
        if self.destroyed or interval_ms <= 0:
            return
        self._heartbeat_timer = threading.Timer(
            interval_ms / 1000, self._send_heartbeat
        )
        self._heartbeat_timer.daemon = True
        self._heartbeat_timer.start()

    def _send_heartbeat(self):
        """Emit a liveness signal and flush it immediately.

        The backend uses these to distinguish 'app is alive with the SDK
        attached' from 'app is quiet' — the gate that makes telemetry-based
        incident resolution safe. Never raises; a failed POST just backs off
        via the normal flush retry path.
        """
        self.emit(DetectionEvent(
            type="system",
            severity="info",
            patternId="heartbeat",
            description="__heartbeat__",
            route="__heartbeat__",
            timestamp=time.time() * 1000,
        ))
        self.flush()
        with self._lock:
            self._schedule_heartbeat()

    def emit(self, event: DetectionEvent):
        if self.config.get("telemetry") is False or self.destroyed:
            return
        with self._lock:
            self.buffer.append(event)
            if len(self.buffer) >= MAX_BUFFER_SIZE:
                self.buffer = self.buffer[-MAX_BUFFER_SIZE:]
            # Flush on a background thread — telemetry must never block the
            # request handler (a slow network POST would stall the app).
            if len(self.buffer) >= MAX_BATCH_SIZE:
                threading.Thread(target=self._flush, daemon=True).start()

    def record_latency(self, ms: float):
        with self._latency_lock:
            self._latency_samples.append(ms)
            if len(self._latency_samples) > 100:
                self._latency_samples = self._latency_samples[-100:]

    def record_route(self, method: str, route: str, status_class: str):
        """Accumulate an observed (method, route, status-class) hit.

        The middleware calls this once per inspected request; counts are
        flushed alongside the regular telemetry batch, so the endpoint
        inventory stays low-volume regardless of traffic spikes."""
        if self.config.get("telemetry") is False or self.destroyed or not route:
            return
        with self._lock:
            key = (method.upper(), route, status_class)
            self._route_inventory[key] = self._route_inventory.get(key, 0) + 1
            if len(self._route_inventory) > 400:
                for k in list(self._route_inventory)[:50]:
                    del self._route_inventory[k]

    def _drain_route_inventory(self) -> list[DetectionEvent]:
        """Convert accumulated route observations into compact telemetry events."""
        with self._lock:
            inventory = self._route_inventory
            self._route_inventory = {}
        now_ms = time.time() * 1000
        events = []
        for (method, route, status_class), count in sorted(inventory.items()):
            events.append(DetectionEvent(
                type="route_inventory",
                severity="info",
                patternId="route_inventory",
                description=status_class,
                route=route,
                method=method,
                count=count,
                timestamp=now_ms,
            ))
        return events

    def _flush(self):
        if self.destroyed:
            return

        # Attach accumulated route-inventory observations to this flush, so
        # the inventory drains even when no detection events are buffered.
        inv = self._drain_route_inventory()

        with self._lock:
            if (not self.buffer and not inv) or not self.project_id:
                self._schedule_flush()
                return
            batch = self.buffer[:MAX_BATCH_SIZE]
            self.buffer = self.buffer[MAX_BATCH_SIZE:]

        if inv:
            room = MAX_BATCH_SIZE - len(batch)
            if room > 0:
                batch = batch + inv[:room]
                if room < len(inv):
                    with self._lock:
                        self.buffer = inv[room:] + self.buffer

        try:
            self._send_batch(batch)
            self.current_flush_interval = DEFAULT_FLUSH_INTERVAL_MS
        except Exception:
            with self._lock:
                self.buffer = batch + self.buffer
            self.current_flush_interval = min(
                self.current_flush_interval * 2, MAX_RETRY_INTERVAL_MS,
            )

        with self._lock:
            self._schedule_flush()

    def _send_batch(self, batch: list[DetectionEvent]):
        url = telemetry_url_for(self.config)

        events_data = []
        for e in batch:
            d = {
                "type": e.type, "severity": e.severity,
                "patternId": e.patternId, "description": e.description,
            }
            route = e.route
            if route:
                d["route"] = _redact_path(route)
            if e.method: d["method"] = e.method
            if e.statusCode: d["http_status"] = e.statusCode
            if e.patternId: d["patternId"] = e.patternId
            if e.type: d["detection_type"] = e.type
            d["event"] = e.description
            d["timestamp"] = int(e.timestamp)
            if e.count: d["count"] = e.count
            events_data.append(d)

        environment = self.config.get("environment") or os.environ.get("SEPTR_ENV") or os.environ.get("ENV", "production")

        avg_latency = 0
        with self._latency_lock:
            if self._latency_samples:
                avg_latency = sum(self._latency_samples) / len(self._latency_samples)
                self._latency_samples.clear()

        payload = json.dumps({
            "events": events_data,
            "projectId": self.project_id,
            "packageName": "septr",
            "packageVersion": _package_version(),
            "environment": environment,
            "avgLatencyMs": round(avg_latency, 2),
            "schemaVersion": "0.1",
            "framework": self.config.get("framework", ""),
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"Septr-Telemetry/{_package_version()}",
        }
        api_key = self.config.get("apiKey")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 201:
                resp.read()

    def send_verified(self, runtime_info: Optional[dict] = None):
        info_str = f" ({json.dumps(runtime_info)})" if runtime_info else ""
        self.emit(DetectionEvent(
            type="system", severity="info", patternId="self_test",
            description=f"Self-test passed{info_str}",
            route="__verified__", timestamp=time.time() * 1000,
        ))

    def send_test_results(self, results: list[dict], runtime_info: Optional[dict] = None):
        """Emit one `__test_result__` event per engine, then a `__verified__` event."""
        for r in results:
            self.emit(DetectionEvent(
                type="system",
                severity="info" if r.get("passed") else "high",
                patternId=f"test_{r.get('engine', '')}",
                description=str(r.get("engine", "")),
                route="__test_result__",
                timestamp=time.time() * 1000,
            ))
        self.send_verified(runtime_info)
        self.flush()

    def flush(self):
        """Send buffered events immediately (used after self-test results)."""
        self._flush()

    def destroy(self):
        self.destroyed = True
        if self._timer:
            self._timer.cancel()
            self._timer = None
        if self._heartbeat_timer:
            self._heartbeat_timer.cancel()
            self._heartbeat_timer = None
        with self._lock:
            self.buffer.clear()

    @property
    def queue_size(self) -> int:
        with self._lock:
            return len(self.buffer)


_default_manager: Optional[TelemetryManager] = None


def _handshake(config: dict) -> Optional[dict]:
    """POST /handshake to verify the API key and fetch project identity.

    Returns the parsed response on success, None on any failure. Never raises.
    """
    api_key = config.get("apiKey") or os.environ.get("SEPTR_API_KEY") or os.environ.get("VS_API_KEY", "")
    if not api_key:
        return None
    base = telemetry_url_for(config)
    if base.endswith("/events"):
        base = base[: -len("/events")]
    url = base.rstrip("/") + "/handshake"
    payload = json.dumps({
        "runtime": config.get("framework", ""),
        "package": "septr",
        "version": _package_version(),
        "environment": config.get("environment") or os.environ.get("SEPTR_ENV") or os.environ.get("ENV", "production"),
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def init_telemetry(config: dict, pid: str):
    global _default_manager
    if _default_manager:
        _default_manager.destroy()

    # Structured v2 keys embed the project id — prefer it over the caller's pid.
    embedded = project_id_from_key(config.get("apiKey", ""))
    resolved_pid = embedded or pid or ""
    _default_manager = TelemetryManager(config, resolved_pid)

    # Fail-loud: warn once when the SEPTR_API_KEY in this process environment
    # differs from the one in a local .env file (shell / launcher export
    # footgun — dotenv loads won't override an already-set env var). Runs even
    # when the app injects the env key into the middleware config explicitly.
    warn_env_vs_dotenv(os.environ.get("SEPTR_API_KEY") or os.environ.get("VS_API_KEY", ""))

    result = _handshake(config)
    if result and result.get("status") == "connected":
        project = result.get("project") or {}
        registered = (result.get("config") or {}).get("registered_url") or ""
        print(
            f"[septr] Connected to project '{project.get('name', resolved_pid)}' "
            f"(id={project.get('id', resolved_pid)})"
            + (f", registered URL {registered}" if registered else "")
            + " — handshake OK",
            flush=True,
        )
    elif config.get("telemetry") is not False:
        print(
            f"[septr] WARNING: handshake failed — check SEPTR_API_KEY and SEPTR_TELEMETRY_URL. "
            f"Retrying in the background.",
            flush=True,
        )
        start_handshake_retry(config, resolved_pid)


def _handshake_retry_loop(config: dict, pid: str, interval: float, stop_event: Optional[threading.Event]) -> None:
    """Retry the startup handshake until it succeeds (backoff, capped at 60s).

    Needed for self-dogfooding apps: the backend handshakes itself during its
    own boot, before the port is listening, so the first attempt always fails.
    """
    import time

    backoff = interval
    while not (stop_event and stop_event.is_set()):
        time.sleep(backoff)
        result = _handshake(config)
        if result and result.get("status") == "connected":
            project = result.get("project") or {}
            registered = (result.get("config") or {}).get("registered_url") or ""
            print(
                f"[septr] Connected to project '{project.get('name', pid)}' "
                f"(id={project.get('id', pid)})"
                + (f", registered URL {registered}" if registered else "")
                + " — handshake OK",
                flush=True,
            )
            return
        backoff = min(backoff * 2, 60.0)


def start_handshake_retry(
    config: dict,
    pid: str,
    interval: float = 10.0,
    stop_event: Optional[threading.Event] = None,
) -> threading.Thread:
    """Start the background handshake retry. Daemon thread — safe to abandon."""
    t = threading.Thread(
        target=_handshake_retry_loop,
        args=(config, pid, interval, stop_event),
        daemon=True,
        name="septr-handshake-retry",
    )
    t.start()
    return t


def emit_event(event: DetectionEvent, config: dict):
    if config.get("telemetry") is False:
        return
    global _default_manager
    if _default_manager and not _default_manager.destroyed:
        _default_manager.emit(event)


def send_verified(runtime_info: Optional[dict] = None):
    global _default_manager
    if _default_manager and not _default_manager.destroyed:
        _default_manager.send_verified(runtime_info)


def send_test_results(results: list[dict], runtime_info: Optional[dict] = None):
    global _default_manager
    if _default_manager and not _default_manager.destroyed:
        _default_manager.send_test_results(results, runtime_info)


def record_latency_ms(ms: float):
    global _default_manager
    if _default_manager and not _default_manager.destroyed:
        _default_manager.record_latency(ms)


def record_route(method: str, route: str, status_class: str):
    """Record one observed (method, route, status-class) hit for the endpoint
    inventory. Call from middleware once per inspected request."""
    global _default_manager
    if _default_manager and not _default_manager.destroyed:
        _default_manager.record_route(method, route, status_class)


def destroy_telemetry():
    global _default_manager
    if _default_manager:
        _default_manager.destroy()
        _default_manager = None
