
import threading
import time


def test_emit_does_not_block_on_flush():
    """emit() must return immediately even when the buffer is full and the
    flush POST is slow — telemetry must never stall request handlers."""
    import time
    from septr.core.telemetry import TelemetryManager, MAX_BATCH_SIZE, DetectionEvent

    manager = TelemetryManager(
        {"telemetry_url": "http://127.0.0.1:1/events", "telemetry": True},
        "test-project",
    )
    t0 = time.time()
    for _ in range(MAX_BATCH_SIZE + 5):
        manager.emit(DetectionEvent(
            type="test", severity="low", patternId="test", description="x",
            route="/x", method="GET", timestamp=0,
        ))
    elapsed = time.time() - t0
    manager.destroy()
    assert elapsed < 0.5, f"emit blocked for {elapsed:.2f}s"


def test_handshake_retry_succeeds_in_background(capsys):
    """The background retry must keep re-handshaking until the backend is
    reachable (self-dogfooding apps handshake during their own boot, before
    the port is listening)."""
    from septr.core import telemetry

    calls = {"n": 0}
    real = telemetry._handshake

    def fake(config):
        calls["n"] += 1
        if calls["n"] < 2:
            return None
        return {"status": "connected", "project": {"id": "p1", "name": "Test Project"}}

    stop = threading.Event()
    telemetry._handshake = fake
    try:
        thread = telemetry.start_handshake_retry({"apiKey": "septr_live_x"}, "p1", interval=0.05, stop_event=stop)
        thread.join(timeout=5)
        assert not thread.is_alive(), "retry thread never finished"
        assert calls["n"] >= 2
        out = capsys.readouterr().out
        assert "handshake OK" in out
        assert "Test Project" in out
    finally:
        telemetry._handshake = real
        stop.set()


def test_handshake_retry_keeps_trying_on_persistent_failure():
    """If the backend never comes up, the retry thread keeps polling."""
    from septr.core import telemetry

    calls = {"n": 0}
    real = telemetry._handshake

    def fake(config):
        calls["n"] += 1
        return None

    stop = threading.Event()
    telemetry._handshake = fake
    try:
        thread = telemetry.start_handshake_retry({"apiKey": "septr_live_x"}, "p1", interval=0.01, stop_event=stop)
        time.sleep(0.3)
        assert calls["n"] >= 3
        assert thread.is_alive()  # still retrying
    finally:
        telemetry._handshake = real
        stop.set()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_heartbeat_interval_parsing(monkeypatch):
    from septr.core.telemetry import heartbeat_interval_ms, DEFAULT_HEARTBEAT_INTERVAL_MS

    monkeypatch.delenv("SEPTR_HEARTBEAT_INTERVAL_MS", raising=False)
    monkeypatch.delenv("VS_HEARTBEAT_INTERVAL_MS", raising=False)
    assert heartbeat_interval_ms() == DEFAULT_HEARTBEAT_INTERVAL_MS

    monkeypatch.setenv("SEPTR_HEARTBEAT_INTERVAL_MS", "5000")
    assert heartbeat_interval_ms() == 5000

    monkeypatch.setenv("SEPTR_HEARTBEAT_INTERVAL_MS", "0")
    assert heartbeat_interval_ms() == 0  # disabled

    monkeypatch.setenv("SEPTR_HEARTBEAT_INTERVAL_MS", "garbage")
    assert heartbeat_interval_ms() == DEFAULT_HEARTBEAT_INTERVAL_MS


def test_heartbeat_emitted_and_flushed():
    """The heartbeat loop must emit a __heartbeat__ system event and flush it
    promptly, without blocking or crashing the manager."""
    from septr.core.telemetry import TelemetryManager, DetectionEvent

    sent = []

    class FakeManager(TelemetryManager):
        def _send_batch(self, batch):
            sent.append(list(batch))

    manager = FakeManager(
        {"telemetry_url": "http://127.0.0.1:1/events", "telemetry": True},
        "test-project",
    )
    manager._send_heartbeat()
    manager.destroy()

    assert len(sent) == 1, f"expected 1 flushed batch, got {len(sent)}"
    events = sent[0]
    assert any(
        e.type == "system" and e.route == "__heartbeat__" and e.description == "__heartbeat__"
        for e in events
    )


def test_heartbeat_disabled_by_env(monkeypatch):
    """interval 0 must prevent the heartbeat timer from ever starting."""
    from septr.core.telemetry import TelemetryManager

    monkeypatch.setenv("SEPTR_HEARTBEAT_INTERVAL_MS", "0")
    manager = TelemetryManager(
        {"telemetry_url": "http://127.0.0.1:1/events", "telemetry": True},
        "test-project",
    )
    assert manager._heartbeat_timer is None
    manager.destroy()


def test_route_inventory_aggregates_and_drains():
    """Route observations accumulate counts and drain as compact inventory
    events with the aggregated count preserved."""
    from septr.core.telemetry import TelemetryManager

    manager = TelemetryManager(
        {"telemetry_url": "http://127.0.0.1:1/events", "telemetry": True},
        "test-project",
    )
    manager.record_route("GET", "/api/users/{id}", "2xx")
    manager.record_route("GET", "/api/users/{id}", "2xx")
    manager.record_route("GET", "/api/users/{id}", "2xx")
    manager.record_route("POST", "/api/users", "4xx")
    manager.record_route("GET", "/api/users/{id}", "2xx")

    events = manager._drain_route_inventory()
    by_key = {(e.method, e.route, e.description): e.count for e in events}
    assert by_key.get(("GET", "/api/users/{id}", "2xx")) == 4
    assert by_key.get(("POST", "/api/users", "4xx")) == 1
    assert all(e.type == "route_inventory" for e in events)
    # Drained inventory is empty on the next call.
    assert manager._drain_route_inventory() == []
    manager.destroy()


def test_route_inventory_skipped_when_telemetry_disabled():
    """record_route must be a no-op when telemetry is disabled."""
    from septr.core.telemetry import TelemetryManager

    manager = TelemetryManager(
        {"telemetry_url": "http://127.0.0.1:1/events", "telemetry": False},
        "test-project",
    )
    manager.record_route("GET", "/api/x", "2xx")
    assert manager._drain_route_inventory() == []
    manager.destroy()


def test_route_inventory_seeds_from_app_routes():
    """Middleware startup seeds the inventory from the app's route table so
    protected endpoints appear even when outer auth middleware hides traffic."""
    import septr.adapters.fastapi as fastapi_mod
    from septr.adapters.fastapi import SeptrASGIMiddleware

    seeded: dict[tuple[str, str, str], int] = {}
    real_record = fastapi_mod.record_route

    def fake_record(method, route, status_class):
        key = (method, route, status_class)
        seeded[key] = seeded.get(key, 0) + 1

    class FakeApp:
        def __init__(self):
            class R:
                def __init__(self, path, methods):
                    self.path = path
                    self.methods = methods
            self.routes = [
                R("/api/users", {"GET", "POST"}),
                R("/api/users/{user_id}", {"GET", "PUT", "DELETE"}),
                R("/__septr_ping", {"GET"}),
                R("/static/{path:path}", {"GET"}),
            ]

    mw = SeptrASGIMiddleware(FakeApp(), {"apiKey": "septr_live_x", "telemetry": False})
    fastapi_mod.record_route = fake_record
    try:
        mw._seed_route_inventory()
    finally:
        fastapi_mod.record_route = real_record

    assert seeded.get(("GET", "/api/users", "reg")) == 1
    assert seeded.get(("POST", "/api/users", "reg")) == 1
    assert seeded.get(("DELETE", "/api/users/{user_id}", "reg")) == 1
    # Self-test ping and static mounts are excluded.
    assert not any(r == "/__septr_ping" for (_, r, _) in seeded)
    assert not any(r.startswith("/static") for (_, r, _) in seeded)
