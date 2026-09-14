import time

from septr.core.safety import EngineGuard, kill_switch_engaged


def _boom():
    raise RuntimeError("boom")


def test_guard_passes_result_through():
    g = EngineGuard()
    assert g.run("e", lambda: 42, 0) == 42
    assert not g.is_open("e")


def test_guard_returns_default_on_exception():
    g = EngineGuard(failure_threshold=3)
    assert g.run("e", _boom, "default") == "default"
    assert not g.is_open("e")


def test_guard_opens_after_threshold_and_reports_once():
    reported = []
    g = EngineGuard(failure_threshold=2, on_degraded=lambda e, r: reported.append((e, r)))

    assert g.run("e", _boom, None) is None
    assert g.run("e", _boom, None) is None
    assert g.is_open("e")

    # Once open, the engine is skipped entirely — fn is never called again.
    assert g.run("e", lambda: 1, 0) == 0
    assert reported == [("e", "RuntimeError: boom")]


def test_guard_budget_marks_slow_calls():
    g = EngineGuard(failure_threshold=1, budget_ms=1)
    assert g.run("e", lambda: (time.sleep(0.02), "ok")[1], None) == "ok"
    assert g.is_open("e")


def test_guard_isolated_per_engine():
    g = EngineGuard(failure_threshold=1)
    assert g.run("a", _boom, None) is None
    assert g.is_open("a")
    assert not g.is_open("b")
    assert g.run("b", lambda: 1, 0) == 1


def test_guard_degraded_callback_errors_do_not_raise():
    def bad_report(engine, reason):
        raise RuntimeError("reporting is best-effort")
    g = EngineGuard(failure_threshold=1, on_degraded=bad_report)
    assert g.run("e", _boom, None) is None
    assert g.is_open("e")


def test_kill_switch_env(monkeypatch):
    monkeypatch.setenv("SEPTR_DISABLED", "true")
    assert kill_switch_engaged({})
    monkeypatch.setenv("SEPTR_DISABLED", "0")
    assert not kill_switch_engaged({})


def test_kill_switch_config():
    assert kill_switch_engaged({"disabled": True})
    assert not kill_switch_engaged({"disabled": False})
