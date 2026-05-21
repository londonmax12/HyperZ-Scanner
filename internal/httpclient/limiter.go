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
}

func NewHostLimiter(rps float64, burst int) *HostLimiter {
	if burst < 1 {
		burst = 1
	}
	return &HostLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rate.Limit(rps),
		burst:    burst,
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
