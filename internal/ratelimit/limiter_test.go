package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := New(3, time.Second)

	for i := 0; i < 3; i++ {
		if !l.Allow("cn") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow("cn") {
		t.Fatal("4th request should be denied")
	}
	// different key is independent
	if !l.Allow("other") {
		t.Fatal("different CN should be allowed")
	}
}

func TestLimiterWindowExpiry(t *testing.T) {
	l := New(1, 50*time.Millisecond)
	if !l.Allow("cn") {
		t.Fatal("first should be allowed")
	}
	if l.Allow("cn") {
		t.Fatal("second should be denied")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow("cn") {
		t.Fatal("should be allowed after window expires")
	}
}
