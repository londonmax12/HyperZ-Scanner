package httpclient

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// ErrBudgetExhausted is returned by Budget.Wait once the scan-wide request
// count cap has been hit. Callers should surface this distinctly from a
// network failure: it's a planned ceiling, not a malfunction.
var ErrBudgetExhausted = errors.New("scan request budget exhausted")

// Budget is the scan-wide ceiling layered on top of the per-host limiter.
// Two independent knobs:
//
//   - count cap (Max): hard quota on total requests for the whole scan;
//     when depleted, Wait returns ErrBudgetExhausted without blocking.
//   - global rate (GlobalRPS): RPS ceiling across all hosts, so fan-out
//     across many targets can't slip past a global noise budget.
//
// Either or both may be disabled. NewBudget returns nil when both are off
// so the client can skip the per-request hop entirely.
type Budget struct {
	max         int64
	used        atomic.Int64
	global      *rate.Limiter
	mu          sync.Mutex
	exhaustedAt time.Time
}

// NewBudget builds a Budget enforcing maxRequests (count cap, 0 = unlimited)
// and globalRPS (global rate, 0 = unlimited). burst applies only when
// globalRPS > 0; values below 1 are clamped to 1 so a token is always
// available immediately.
//
// Returns nil when both knobs are off; the client treats a nil Budget as
// "no enforcement" and skips the per-request hop.
func NewBudget(maxRequests int64, globalRPS float64, burst int) *Budget {
	if maxRequests <= 0 && globalRPS <= 0 {
		return nil
	}
	b := &Budget{}
	if maxRequests > 0 {
		b.max = maxRequests
	}
	if globalRPS > 0 {
		if burst < 1 {
			burst = 1
		}
		b.global = rate.NewLimiter(rate.Limit(globalRPS), burst)
	}
	return b
}

// Wait reserves one slot from the budget. If the count cap is in effect and
// already depleted, returns ErrBudgetExhausted without waiting. Otherwise
// waits for the global rate limiter (if any), then claims the slot
// atomically. ctx cancellation propagates from the rate-limiter wait.
//
// The cap is re-checked after the rate wait because concurrent callers may
// have drained the remaining slots while we were queued; the CAS loop hands
// the last few slots out deterministically and the rest get ErrBudgetExhausted.
func (b *Budget) Wait(ctx context.Context) error {
	if b == nil {
		return nil
	}
	if b.max > 0 && b.used.Load() >= b.max {
		b.markExhausted()
		return ErrBudgetExhausted
	}
	if b.global != nil {
		if err := b.global.Wait(ctx); err != nil {
			return err
		}
	}
	if b.max > 0 {
		for {
			cur := b.used.Load()
			if cur >= b.max {
				b.markExhausted()
				return ErrBudgetExhausted
			}
			if b.used.CompareAndSwap(cur, cur+1) {
				return nil
			}
		}
	}
	b.used.Add(1)
	return nil
}

func (b *Budget) markExhausted() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exhaustedAt.IsZero() {
		b.exhaustedAt = time.Now()
	}
}

// BudgetStats is a read-only snapshot of a Budget for reports and logging.
// Max == 0 means the count cap was off; GlobalRPS == 0 means the rate
// ceiling was off. Exhausted is set the first time Wait observed the cap
// fully drained, even if subsequent callers consumed the same condition.
type BudgetStats struct {
	Requests    int64     `json:"requests"`
	Max         int64     `json:"max,omitempty"`
	GlobalRPS   float64   `json:"global_rps,omitempty"`
	Exhausted   bool      `json:"exhausted,omitempty"`
	ExhaustedAt time.Time `json:"exhausted_at,omitempty"`
}

// Snapshot captures the current Budget state. Safe to call concurrently
// with Wait; values reflect a consistent point-in-time view (the counter
// is read atomically, the exhausted marker under the mutex).
func (b *Budget) Snapshot() BudgetStats {
	if b == nil {
		return BudgetStats{}
	}
	b.mu.Lock()
	exh := b.exhaustedAt
	b.mu.Unlock()
	var rps float64
	if b.global != nil {
		rps = float64(b.global.Limit())
	}
	return BudgetStats{
		Requests:    b.used.Load(),
		Max:         b.max,
		GlobalRPS:   rps,
		Exhausted:   !exh.IsZero(),
		ExhaustedAt: exh,
	}
}
