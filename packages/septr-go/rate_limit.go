package septr

import (
	"sync"
	"time"
)

type rateLimitEntry struct {
	count      int
	windowStart int64
}

type SlidingWindowRateLimiter struct {
	mu       sync.Mutex
	store    map[string]*rateLimitEntry
	max      int
	windowMs int64
}

func NewSlidingWindowRateLimiter(max int, windowMs int) *SlidingWindowRateLimiter {
	return &SlidingWindowRateLimiter{
		store:    make(map[string]*rateLimitEntry),
		max:      max,
		windowMs: int64(windowMs),
	}
}

func (l *SlidingWindowRateLimiter) Check(key string) (allowed bool, remaining int, resetMs int64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().UnixMilli()
	entry, exists := l.store[key]

	if !exists || now-entry.windowStart > l.windowMs {
		l.store[key] = &rateLimitEntry{count: 1, windowStart: now}
		return true, l.max - 1, l.windowMs
	}

	if entry.count >= l.max {
		return false, 0, l.windowMs - (now - entry.windowStart)
	}

	entry.count++
	return true, l.max - entry.count, l.windowMs - (now - entry.windowStart)
}

func (l *SlidingWindowRateLimiter) Destroy() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.store = make(map[string]*rateLimitEntry)
}
