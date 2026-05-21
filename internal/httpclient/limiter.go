package httpclient

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

type HostLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rps      rate.Limit
	burst    int
	// minRPS is the floor Penalize will not decay below, so a noisy
	// host can slow us down but never quite stall us out.
	minRPS rate.Limit
}

func NewHostLimiter(rps float64, burst int) *HostLimiter {
	if burst < 1 {
		burst = 1
	}
	return &HostLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rate.Limit(rps),
		burst:    burst,
		minRPS:   rate.Limit(0.1),
	}
}

func (h *HostLimiter) Wait(ctx context.Context, host string) error {
	h.mu.Lock()
	lim, ok := h.limiters[host]
	if !ok {
		lim = rate.NewLimiter(h.rps, h.burst)
		h.limiters[host] = lim
	}
	h.mu.Unlock()
	return lim.Wait(ctx)
}

// Penalize halves the current per-host rate (floored at minRPS) so subsequent
// requests to a host that pushed back (429/503) slow down. Recovery is not
// automatic; the limiter stays slow for the rest of the scan.
func (h *HostLimiter) Penalize(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	lim, ok := h.limiters[host]
	if !ok {
		// Materialize so the next Wait already sees the penalized rate.
		lim = rate.NewLimiter(h.rps, h.burst)
		h.limiters[host] = lim
	}
	next := lim.Limit() / 2
	if next < h.minRPS {
		next = h.minRPS
	}
	lim.SetLimit(next)
}

// Limit returns the current per-host rate (for tests / introspection). Returns
// 0 if the host has not been seen yet.
func (h *HostLimiter) Limit(host string) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	lim, ok := h.limiters[host]
	if !ok {
		return 0
	}
	return float64(lim.Limit())
}
