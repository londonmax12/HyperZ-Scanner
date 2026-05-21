package proxy

import (
	"math"
	"net/url"
	"sync"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestProxyStatSuccessRate(t *testing.T) {
	cases := []struct {
		name string
		stat ProxyStat
		want float64
	}{
		{"zero requests", ProxyStat{}, 0},
		{"all success", ProxyStat{Requests: 4, Successes: 4}, 1.0},
		{"half success", ProxyStat{Requests: 10, Successes: 5}, 0.5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.stat.SuccessRate(); math.Abs(got-c.want) > 1e-9 {
				t.Fatalf("SuccessRate = %v, want %v", got, c.want)
			}
		})
	}
}

func TestProxyStatBlockRate(t *testing.T) {
	cases := []struct {
		name string
		stat ProxyStat
		want float64
	}{
		{"no traffic", ProxyStat{}, 0},
		// Errors are excluded from denominator.
		{"errors only", ProxyStat{Requests: 5, Errors: 5}, 0},
		{"half blocked", ProxyStat{Requests: 4, Successes: 2, Blocks: 2}, 0.5},
		{"all blocked", ProxyStat{Requests: 3, Blocks: 3}, 1.0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.stat.BlockRate(); math.Abs(got-c.want) > 1e-9 {
				t.Fatalf("BlockRate = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSmartPoolLenNilSafe(t *testing.T) {
	var p *SmartPool
	if p.Len() != 0 {
		t.Fatalf("nil pool Len = %d, want 0", p.Len())
	}
	if got := p.Stats(); got != nil {
		t.Fatalf("nil pool Stats = %v, want nil", got)
	}
	if got := p.OverallBlockRate(); got != 0 {
		t.Fatalf("nil pool OverallBlockRate = %v, want 0", got)
	}
	if got := p.next(); got != nil {
		t.Fatalf("nil pool next = %v, want nil", got)
	}
}

func TestSmartPoolEmptyNext(t *testing.T) {
	p := NewSmartPool(nil)
	if p.Len() != 0 {
		t.Fatalf("empty pool Len = %d", p.Len())
	}
	if got := p.next(); got != nil {
		t.Fatalf("empty pool next = %v, want nil", got)
	}
}

func TestSmartPoolSingleEntryAlwaysSelected(t *testing.T) {
	u := mustURL(t, "http://only.example:1")
	p := NewSmartPool([]*url.URL{u})
	for i := 0; i < 50; i++ {
		e := p.next()
		if e == nil || e.url != u {
			t.Fatalf("iter %d: got %v, want %v", i, e, u)
		}
	}
}

func TestSmartPoolRecordCountsByOutcome(t *testing.T) {
	u := mustURL(t, "http://a.example:1")
	p := NewSmartPool([]*url.URL{u})
	e := p.entries[0]
	p.Record(e, OutcomeSuccess)
	p.Record(e, OutcomeSuccess)
	p.Record(e, OutcomeBlock)
	p.Record(e, OutcomeError)
	// nil entry is a no-op.
	p.Record(nil, OutcomeSuccess)

	got := p.Stats()[0]
	want := ProxyStat{URL: u, Requests: 4, Successes: 2, Blocks: 1, Errors: 1}
	if got.Requests != want.Requests || got.Successes != want.Successes ||
		got.Blocks != want.Blocks || got.Errors != want.Errors {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}
}

func TestSmartPoolRecordConcurrent(t *testing.T) {
	u := mustURL(t, "http://busy.example:1")
	p := NewSmartPool([]*url.URL{u})
	e := p.entries[0]
	const goroutines, perG = 16, 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				p.Record(e, OutcomeSuccess)
			}
		}()
	}
	wg.Wait()
	got := p.Stats()[0]
	if got.Requests != int64(goroutines*perG) || got.Successes != int64(goroutines*perG) {
		t.Fatalf("concurrent stats = %+v, want req=ok=%d", got, goroutines*perG)
	}
}

func TestSmartPoolStatsSortedByRequests(t *testing.T) {
	a := mustURL(t, "http://a.example:1")
	b := mustURL(t, "http://b.example:1")
	c := mustURL(t, "http://c.example:1")
	p := NewSmartPool([]*url.URL{a, b, c})
	// Give b the most traffic, a the next, c the least.
	for i := 0; i < 5; i++ {
		p.Record(p.entries[1], OutcomeSuccess)
	}
	for i := 0; i < 3; i++ {
		p.Record(p.entries[0], OutcomeSuccess)
	}
	p.Record(p.entries[2], OutcomeSuccess)

	stats := p.Stats()
	if len(stats) != 3 {
		t.Fatalf("len(stats) = %d, want 3", len(stats))
	}
	if stats[0].URL != b || stats[1].URL != a || stats[2].URL != c {
		t.Fatalf("stats order = %v %v %v, want b a c",
			stats[0].URL, stats[1].URL, stats[2].URL)
	}
}

func TestSmartPoolOverallBlockRate(t *testing.T) {
	a := mustURL(t, "http://a.example:1")
	b := mustURL(t, "http://b.example:1")
	p := NewSmartPool([]*url.URL{a, b})
	// a: 3 successes, 1 block. b: 1 success, 5 errors (errors excluded).
	for i := 0; i < 3; i++ {
		p.Record(p.entries[0], OutcomeSuccess)
	}
	p.Record(p.entries[0], OutcomeBlock)
	p.Record(p.entries[1], OutcomeSuccess)
	for i := 0; i < 5; i++ {
		p.Record(p.entries[1], OutcomeError)
	}
	// blocks=1, successes=4 → 1/5 = 0.2
	if got := p.OverallBlockRate(); math.Abs(got-0.2) > 1e-9 {
		t.Fatalf("OverallBlockRate = %v, want 0.2", got)
	}
}

func TestSmartPoolScoreLaplaceSmoothing(t *testing.T) {
	// Untouched entry starts at (0+1)/(0+2) = 0.5.
	e := &proxyEntry{}
	if got := e.score(); math.Abs(got-0.5) > 1e-9 {
		t.Fatalf("fresh score = %v, want 0.5", got)
	}
	// One failure on a new proxy: (0+1)/(1+2) ≈ 0.333.
	e.requests.Add(1)
	if got := e.score(); math.Abs(got-1.0/3.0) > 1e-9 {
		t.Fatalf("1-fail score = %v, want 1/3", got)
	}
}
