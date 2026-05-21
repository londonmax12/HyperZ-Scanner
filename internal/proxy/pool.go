// Package proxy holds the proxy pool used by the HTTP client. The pool tracks
// per-proxy outcomes (success, target block, proxy/network error) and selects
// the next proxy via epsilon-greedy on Laplace-smoothed success rate, so bad
// proxies fade out automatically while new ones still get tried.
package proxy

import (
	"math/rand/v2"
	"net/url"
	"sort"
	"sync/atomic"
)

// Outcome classifies the result of a single request through a proxy.
type Outcome int

const (
	OutcomeSuccess Outcome = iota
	// OutcomeBlock means the target server rejected the request (403, 429).
	// It signals scan health, not proxy health — but still counts against
	// the proxy's score since a blocked proxy is useless for further work.
	OutcomeBlock
	// OutcomeError means the proxy or network failed (5xx-from-proxy,
	// dial/timeout/TLS errors). Proxy is likely degraded.
	OutcomeError
)

const defaultEpsilon = 0.15

// ProxyStat is a read-only snapshot of one proxy's counters, for reporting.
type ProxyStat struct {
	URL       *url.URL
	Requests  int64
	Successes int64
	Blocks    int64
	Errors    int64
}

// SuccessRate returns successes / requests, or 0 if no requests yet.
func (s ProxyStat) SuccessRate() float64 {
	if s.Requests == 0 {
		return 0
	}
	return float64(s.Successes) / float64(s.Requests)
}

// BlockRate returns blocks / (blocks + successes), the fraction of completed
// requests the target rejected. Errors are excluded since they don't tell us
// anything about target acceptance.
func (s ProxyStat) BlockRate() float64 {
	denom := s.Blocks + s.Successes
	if denom == 0 {
		return 0
	}
	return float64(s.Blocks) / float64(denom)
}

type proxyEntry struct {
	url       *url.URL
	requests  atomic.Int64
	successes atomic.Int64
	blocks    atomic.Int64
	errors    atomic.Int64
}

// score is Laplace-smoothed success rate. A new proxy starts at 0.5, so it's
// preferred over a proxy with established failures; one failure on a new proxy
// drops it slightly but doesn't kill it outright.
func (e *proxyEntry) score() float64 {
	n := e.requests.Load()
	s := e.successes.Load()
	return float64(s+1) / float64(n+2)
}

type SmartPool struct {
	entries []*proxyEntry
	epsilon float64
}

func NewSmartPool(proxies []*url.URL) *SmartPool {
	entries := make([]*proxyEntry, 0, len(proxies))
	for _, u := range proxies {
		entries = append(entries, &proxyEntry{url: u})
	}
	return &SmartPool{entries: entries, epsilon: defaultEpsilon}
}

func (p *SmartPool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.entries)
}

// next returns the proxy entry to use for the next request, or nil if the
// pool is empty. Epsilon-greedy: with probability epsilon pick uniformly at
// random (explore), otherwise pick the highest-scoring proxy (exploit).
func (p *SmartPool) next() *proxyEntry {
	if p == nil || len(p.entries) == 0 {
		return nil
	}
	if len(p.entries) == 1 {
		return p.entries[0]
	}
	if rand.Float64() < p.epsilon {
		return p.entries[rand.IntN(len(p.entries))]
	}
	best := p.entries[0]
	bestScore := best.score()
	for _, e := range p.entries[1:] {
		if s := e.score(); s > bestScore {
			best, bestScore = e, s
		}
	}
	return best
}

// Record updates the counters for a proxy after a request completes. Safe
// to call from many goroutines; the entry pointer must come from a prior
// selection via the RoundTripper.
func (p *SmartPool) Record(e *proxyEntry, o Outcome) {
	if e == nil {
		return
	}
	e.requests.Add(1)
	switch o {
	case OutcomeSuccess:
		e.successes.Add(1)
	case OutcomeBlock:
		e.blocks.Add(1)
	case OutcomeError:
		e.errors.Add(1)
	}
}

// Stats returns a snapshot of every proxy's counters, sorted by request
// count descending so the busiest proxies come first.
func (p *SmartPool) Stats() []ProxyStat {
	if p == nil {
		return nil
	}
	out := make([]ProxyStat, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, ProxyStat{
			URL:       e.url,
			Requests:  e.requests.Load(),
			Successes: e.successes.Load(),
			Blocks:    e.blocks.Load(),
			Errors:    e.errors.Load(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out
}

// OverallBlockRate aggregates blocks / (blocks + successes) across all
// proxies — answers "how often is the scan getting rejected overall."
func (p *SmartPool) OverallBlockRate() float64 {
	if p == nil {
		return 0
	}
	var blocks, successes int64
	for _, e := range p.entries {
		blocks += e.blocks.Load()
		successes += e.successes.Load()
	}
	denom := blocks + successes
	if denom == 0 {
		return 0
	}
	return float64(blocks) / float64(denom)
}
