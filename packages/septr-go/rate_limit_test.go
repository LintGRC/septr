package septr

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsFirst(t *testing.T) {
	l := NewSlidingWindowRateLimiter(5, 60000)
	allowed, remaining, _ := l.Check("test")
	if !allowed || remaining != 4 {
		t.Fatalf("expected allowed=true remaining=4 got allowed=%v remaining=%d", allowed, remaining)
	}
}

func TestRateLimiter_BlocksAfterMax(t *testing.T) {
	l := NewSlidingWindowRateLimiter(2, 60000)
	for i := 0; i < 2; i++ {
		allowed, _, _ := l.Check("key")
		if !allowed {
			t.Fatalf("expected allowed on attempt %d", i+1)
		}
	}
	allowed, _, _ := l.Check("key")
	if allowed {
		t.Fatal("expected blocked on third attempt")
	}
}

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	l := NewSlidingWindowRateLimiter(1, 100)
	l.Check("key")
	time.Sleep(150 * time.Millisecond)
	allowed, _, _ := l.Check("key")
	if !allowed {
		t.Fatal("expected allowed after window reset")
	}
}

func TestRateLimiter_DifferentKeys(t *testing.T) {
	l := NewSlidingWindowRateLimiter(1, 60000)
	a1, _, _ := l.Check("a")
	b1, _, _ := l.Check("b")
	if !a1 || !b1 {
		t.Fatal("expected both allowed")
	}
}

func TestRateLimiter_Remaining(t *testing.T) {
	l := NewSlidingWindowRateLimiter(5, 60000)
	_, r1, _ := l.Check("key")
	_, r2, _ := l.Check("key")
	if r1 != 4 || r2 != 3 {
		t.Fatalf("expected 4 then 3, got %d then %d", r1, r2)
	}
}

func TestRateLimiter_Destroy(t *testing.T) {
	l := NewSlidingWindowRateLimiter(1, 60000)
	l.Check("key")
	l.Destroy()
	if len(l.store) != 0 {
		t.Fatal("expected empty store after destroy")
	}
}
