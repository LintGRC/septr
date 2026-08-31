import pytest
import time
from septr.core.rate_limit import SlidingWindowRateLimiter


class TestSlidingWindowRateLimiter:
    def test_allows_first_request(self):
        limiter = SlidingWindowRateLimiter(5, 60000)
        result = limiter.check("test-key")
        assert result["allowed"] is True
        assert result["remaining"] == 4

    def test_blocks_after_max(self):
        limiter = SlidingWindowRateLimiter(2, 60000)
        assert limiter.check("key")["allowed"] is True
        assert limiter.check("key")["allowed"] is True
        assert limiter.check("key")["allowed"] is False

    def test_resets_after_window(self):
        limiter = SlidingWindowRateLimiter(1, 100)
        assert limiter.check("key")["allowed"] is True
        assert limiter.check("key")["allowed"] is False
        time.sleep(0.15)
        assert limiter.check("key")["allowed"] is True

    def test_different_keys_independent(self):
        limiter = SlidingWindowRateLimiter(1, 60000)
        assert limiter.check("key-a")["allowed"] is True
        assert limiter.check("key-b")["allowed"] is True

    def test_remaining_decrements(self):
        limiter = SlidingWindowRateLimiter(5, 60000)
        assert limiter.check("key")["remaining"] == 4
        assert limiter.check("key")["remaining"] == 3
        assert limiter.check("key")["remaining"] == 2

    def test_destroy_clears_store(self):
        limiter = SlidingWindowRateLimiter(1, 60000)
        limiter.check("key")
        limiter.destroy()
        assert limiter._store == {}


if __name__ == "__main__":
    pytest.main()
