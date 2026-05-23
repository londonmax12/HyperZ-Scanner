package httpclient

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewBudgetReturnsNilWhenBothDisabled(t *testing.T) {
	if b := NewBudget(0, 0, 1); b != nil {
		t.Fatalf("NewBudget(0,0,1) = %v, want nil so callers skip the per-request hop", b)
	}
	if b := NewBudget(-1, -1, 1); b != nil {
		t.Fatalf("NewBudget(-1,-1,1) = %v, want nil (negatives must collapse to disabled)", b)
	}
}

func TestBudgetWaitOnNilIsNoop(t *testing.T) {
	// Wait must tolerate a nil receiver so client doWith can call it
	// unconditionally without paying a nil-check on the hot path.
	var b *Budget
	if err := b.Wait(context.Background()); err != nil {
		t.Fatalf("nil-Budget.Wait = %v, want nil", err)
	}
}

func TestBudgetCountExhaustsAfterMaxRequests(t *testing.T) {
	b := NewBudget(3, 0, 1)
	for i := 0; i < 3; i++ {
		if err := b.Wait(context.Background()); err != nil {
			t.Fatalf("Wait %d: %v, want nil within budget", i, err)
		}
	}
	if err := b.Wait(context.Background()); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Wait past cap = %v, want ErrBudgetExhausted", err)
	}
	// Further attempts keep failing fast - the budget doesn't recover.
	if err := b.Wait(context.Background()); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Wait after exhaustion = %v, want ErrBudgetExhausted again", err)
	}
}

func TestBudgetGlobalRPSPaces(t *testing.T) {
	// rps=2, burst=1: the second Wait must wait ~500ms for the next token.
	b := NewBudget(0, 2, 1)
	start := time.Now()
	for i := 0; i < 2; i++ {
		if err := b.Wait(context.Background()); err != nil {
			t.Fatalf("Wait %d: %v", i, err)
		}
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("two Waits at 2rps/burst1 took %v, expected ≥300ms", d)
	}
}

func TestBudgetGlobalRPSContextCancellation(t *testing.T) {
	b := NewBudget(0, 0.01, 1) // very slow
	if err := b.Wait(context.Background()); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := b.Wait(ctx); err == nil {
		t.Fatal("expected context deadline error while waiting for global RPS token")
	}
}

func TestBudgetConcurrentClaimDoesNotOvershootCap(t *testing.T) {
	// 50 goroutines racing for a cap of 10: exactly 10 must succeed, the
	// remaining 40 must observe ErrBudgetExhausted. Without the CAS loop
	// inside Wait this would race and over-claim.
	b := NewBudget(10, 0, 1)
	var ok, denied atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := b.Wait(context.Background()); err == nil {
				ok.Add(1)
			} else if errors.Is(err, ErrBudgetExhausted) {
				denied.Add(1)
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 10 {
		t.Fatalf("granted = %d, want exactly 10", ok.Load())
	}
	if denied.Load() != 40 {
		t.Fatalf("denied = %d, want 40 (50 - 10 granted)", denied.Load())
	}
}

func TestBudgetSnapshotTracksUseAndExhaustion(t *testing.T) {
	b := NewBudget(2, 5, 1)
	_ = b.Wait(context.Background())
	s := b.Snapshot()
	if s.Requests != 1 || s.Max != 2 || s.GlobalRPS != 5 || s.Exhausted {
		t.Fatalf("snapshot after 1 wait = %+v, want {1,2,5,false,...}", s)
	}
	_ = b.Wait(context.Background())
	_ = b.Wait(context.Background()) // this one fails - cap is 2
	s = b.Snapshot()
	if !s.Exhausted {
		t.Fatalf("snapshot Exhausted = false, want true after exceeding cap")
	}
	if s.ExhaustedAt.IsZero() {
		t.Fatalf("snapshot ExhaustedAt = zero, want non-zero")
	}
	if s.Requests != 2 {
		t.Fatalf("snapshot Requests = %d, want 2 (the rejected call must not increment)", s.Requests)
	}
}

func TestBudgetSnapshotOnNilIsZeroValue(t *testing.T) {
	var b *Budget
	if got := b.Snapshot(); got != (BudgetStats{}) {
		t.Fatalf("nil-Budget.Snapshot = %+v, want zero value", got)
	}
}
