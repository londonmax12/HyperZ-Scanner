package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// TestTransportRoutesThroughProxy stands up a fake HTTP proxy and confirms
// that requests through the smart pool's RoundTripper actually go via that
// proxy (HTTP proxies receive a request whose URL contains the full target).
func TestTransportRoutesThroughProxy(t *testing.T) {
	var hits atomic.Int64
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// HTTP proxies receive an absolute-form URI in the request line.
		if !strings.HasPrefix(r.RequestURI, "http://") {
			t.Errorf("expected absolute request URI, got %q", r.RequestURI)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer proxySrv.Close()

	pu, _ := url.Parse(proxySrv.URL)
	pool := NewSmartPool([]*url.URL{pu})
	rt := NewTransport(pool, TransportConfig{})
	client := &http.Client{Transport: rt}

	for i := 0; i < 3; i++ {
		// Use a non-proxy URL the fake proxy can intercept. The hostname
		// doesn't need to resolve because the proxy answers first.
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.invalid/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("proxy hits = %d, want 3", got)
	}
	stats := pool.Stats()
	if stats[0].Requests != 3 || stats[0].Successes != 3 {
		t.Fatalf("stats = %+v, want req=3 ok=3", stats[0])
	}
}

// TestTransportClassifiesOutcomes verifies that 403/429 → block, 5xx-proxy
// → error, 2xx → success, attributed to the proxy actually used.
func TestTransportClassifiesOutcomes(t *testing.T) {
	var nextStatus atomic.Int32
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(nextStatus.Load()))
	}))
	defer proxySrv.Close()

	pu, _ := url.Parse(proxySrv.URL)
	pool := NewSmartPool([]*url.URL{pu})
	rt := NewTransport(pool, TransportConfig{})
	client := &http.Client{Transport: rt}

	cases := []struct {
		status              int
		wantOK, wantBlock, wantErr int64
	}{
		{200, 1, 0, 0},
		{403, 1, 1, 0},
		{429, 1, 2, 0},
		{503, 1, 2, 1},
		{301, 2, 2, 1},
	}
	for _, c := range cases {
		nextStatus.Store(int32(c.status))
		req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("status %d: %v", c.status, err)
		}
		resp.Body.Close()
		s := pool.Stats()[0]
		if s.Successes != c.wantOK || s.Blocks != c.wantBlock || s.Errors != c.wantErr {
			t.Fatalf("after %d: stats=%+v, want ok=%d block=%d err=%d",
				c.status, s, c.wantOK, c.wantBlock, c.wantErr)
		}
	}
}

// TestEpsilonGreedyPrefersBetterProxy: pool with one "good" and one "bad"
// proxy. Seed stats so the good proxy wins on score, then verify selection
// picks it most of the time (epsilon is 0.15, so ~85% should hit good).
func TestEpsilonGreedyPrefersBetterProxy(t *testing.T) {
	good, _ := url.Parse("http://good.example:1")
	bad, _ := url.Parse("http://bad.example:1")
	pool := NewSmartPool([]*url.URL{good, bad})

	// Seed: good is 100/100 success; bad is 0/100 success.
	for _, e := range pool.entries {
		for i := 0; i < 100; i++ {
			if e.url == good {
				pool.Record(e, OutcomeSuccess)
			} else {
				pool.Record(e, OutcomeError)
			}
		}
	}

	const trials = 1000
	goodPicks := 0
	for i := 0; i < trials; i++ {
		e := pool.next()
		if e.url == good {
			goodPicks++
		}
	}
	// Expect ~85% (exploit) + half of 15% (random tiebreak on explore) ≈ 92.5%.
	// Generous lower bound to keep the test stable under RNG variance.
	if goodPicks < trials*80/100 {
		t.Fatalf("good proxy picked %d/%d, want >= 800", goodPicks, trials)
	}
	if goodPicks > trials*98/100 {
		t.Fatalf("good proxy picked %d/%d — explore branch seems broken", goodPicks, trials)
	}
}
