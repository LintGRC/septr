"""Fail-open safety primitives.

Septr's contract: it must never break or measurably slow the host app. Every
detection engine runs behind a guard that:

  * catches exceptions (an engine bug degrades one detection, never the app),
  * enforces a per-call time budget (a pathological input skips the engine
    instead of stalling the request), and
  * trips a per-engine circuit breaker after repeated failures, so a broken
    engine is skipped for the rest of the process instead of failing (or
    burning time on) every single request.

Tripped engines are reported once to the Septr backend as a ``system`` event
so operators see "engine degraded — upgrade/restart" instead of having to
disable the engine by hand.

``SEPTR_DISABLED=true`` (or ``disabled: true`` in the config) is an emergency
kill switch: the middleware passes every request through untouched while the
SDK stays installed, so on-call never has to uninstall to recover.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Callable, Optional

logger = logging.getLogger("septr")

DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_ENGINE_BUDGET_MS = 50.0

_TRUTHY = {"1", "true", "yes", "on"}


def kill_switch_engaged(config: Optional[dict] = None) -> bool:
    """True when the operator pulled the emergency bypass."""
    if config and config.get("disabled") is True:
        return True
    return (os.environ.get("SEPTR_DISABLED") or "").strip().lower() in _TRUTHY


class EngineGuard:
    """Per-engine fail-open wrapper with a time budget and circuit breaker.

    One instance per middleware. ``on_degraded(engine, reason)`` is invoked at
    most once per engine per process, when the breaker trips.
    """

    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        budget_ms: float = DEFAULT_ENGINE_BUDGET_MS,
        on_degraded: Optional[Callable[[str, str], None]] = None,
    ):
        self._threshold = max(1, int(failure_threshold))
        self._budget_ms = max(0.0, float(budget_ms))
        self._on_degraded = on_degraded
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._open: set[str] = set()
        self._reported: set[str] = set()

    def is_open(self, engine: str) -> bool:
        with self._lock:
            return engine in self._open

    def run(self, engine: str, fn: Callable[[], Any], default: Any) -> Any:
        """Run ``fn`` under the guard; return ``default`` on skip/failure."""
        with self._lock:
            if engine in self._open:
                return default
        start = time.perf_counter()
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 — the guard is the safety net
            self._record_failure(engine, f"{type(exc).__name__}: {exc}")
            return default
        if self._budget_ms:
            elapsed_ms = (time.perf_counter() - start) * 1000
            if elapsed_ms > self._budget_ms:
                self._record_failure(
                    engine,
                    f"took {elapsed_ms:.0f}ms (budget {self._budget_ms:.0f}ms)",
                )
        return result

    def _record_failure(self, engine: str, reason: str) -> None:
        should_report = False
        with self._lock:
            if engine in self._open:
                return
            count = self._failures.get(engine, 0) + 1
            self._failures[engine] = count
            if count >= self._threshold:
                self._open.add(engine)
                if engine not in self._reported:
                    self._reported.add(engine)
                    should_report = True
        logger.warning(
            "septr: engine %r failed %d time(s) (%s)%s",
            engine,
            self._failures.get(engine, 1),
            reason,
            " — disabled for this process" if self.is_open(engine) else "",
        )
        if should_report and self._on_degraded:
            try:
                self._on_degraded(engine, reason)
            except Exception:  # noqa: BLE001 — reporting must never raise
                pass

    def degraded_engines(self) -> list[str]:
        with self._lock:
            return sorted(self._open)


def safe_call(fn: Callable[[], Any], default: Any) -> Any:
    """Run ``fn``, returning ``default`` on any exception. No breaker."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        logger.exception("septr: non-critical call failed")
        return default
