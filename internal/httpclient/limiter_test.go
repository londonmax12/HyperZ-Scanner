package httpclient

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestHostLimiterAllowsBurst(t *testing.T) {
	lim := NewHostLimiter(0.1, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := lim.Wait(ctx, "a.example"); err != nil {
			t.Fatalf("burst %d: %v", i, err)
		}
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("burst of 5 took %v, expected near-instant", d)
	}
}

func TestHostLimiterPerHostIndependent(t *testing.T) {
	// rps=0.1, burst=1: each host gets exactly one immediate token.
	lim := NewHostLimiter(0.1, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	for _, host := range []string{"a.example", "b.example", "c.example"} {
		if err := lim.Wait(ctx, host); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
	}
}

func TestHostLimiterMinBurst(t *testing.T) {
	// burst<1 should be clamped to 1; otherwise a token couldn't be acquired
	// even on first try.
	lim := NewHostLimiter(100, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := lim.Wait(ctx, "a.example"); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestHostLimiterContextCancellation(t *testing.T) {
	lim := NewHostLimiter(0.01, 1) // very slow
	if err := lim.Wait(context.Background(), "h"); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := lim.Wait(ctx, "h"); err == nil {
		t.Fatal("expected context deadline error")
	}
}

func TestHostLimiterConcurrentSameHostShares(t *testing.T) {
	// Two goroutines hitting the same host should both observe the same
	// limiter (i.e., map access is thread-safe and reuse occurs).
	lim := NewHostLimiter(100, 10)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = lim.Wait(context.Background(), "shared.example")
		}()
	}
	wg.Wait()
	lim.mu.Lock()
	defer lim.mu.Unlock()
	if len(lim.limiters) != 1 {
		t.Fatalf("expected 1 inner limiter, got %d", len(lim.limiters))
	}
}
