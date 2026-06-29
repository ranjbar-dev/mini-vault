package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-key sliding-window rate limiter.
type Limiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	entries map[string][]time.Time
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{
		window:  window,
		max:     max,
		entries: make(map[string][]time.Time),
	}
}

// Allow returns true if key is within the rate limit.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	ts := l.entries[key]
	// drop timestamps outside the window
	valid := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= l.max {
		l.entries[key] = valid
		return false
	}
	l.entries[key] = append(valid, now)
	return true
}
