import time
import threading


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 60, window_ms: int = 60000):
        self.max = max_requests
        self.window_ms = window_ms
        self._store: dict[str, dict] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> dict:
        now = time.time() * 1000
        with self._lock:
            entry = self._store.get(key)
            if entry is None or now - entry["start"] > self.window_ms:
                self._store[key] = {"count": 1, "start": now}
                return {"allowed": True, "remaining": self.max - 1, "resetMs": self.window_ms}
            if entry["count"] >= self.max:
                return {
                    "allowed": False,
                    "remaining": 0,
                    "resetMs": int(self.window_ms - (now - entry["start"])),
                }
            entry["count"] += 1
            return {
                "allowed": True,
                "remaining": self.max - entry["count"],
                "resetMs": int(self.window_ms - (now - entry["start"])),
            }

    def destroy(self):
        with self._lock:
            self._store.clear()
