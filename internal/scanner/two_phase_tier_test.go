package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// barrierTwoPhase records start / end timestamps for every Plant and
// Detect call so the test can assert the TierActive -> TierDeferred
// barrier: every Plant across every target must complete before the
// first Detect begins. Plant carries a small delay so the in-flight
// window is wide enough that a missing barrier would produce visible
// overlap.
type barrierTwoPhase struct {
	stubCheck
	plantDelay time.Duration

	mu         sync.Mutex
	plantWins  []timeWindow
	detectWins []timeWindow
	detectBody []string
	// extraURLs are KindPage URLs the test wants the check to emit
	// at TierDeferred during Plant. Replaces the legacy
	// DetectURLs() return path; the check now pushes via
	// core.DiscoverAt so emission is on the same code path as the
	// real catalog uses.
	extraURLs []string
}

type timeWindow struct {
	url   string
	start time.Time
	end   time.Time
}

func (b *barrierTwoPhase) Plant(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	start := time.Now()
	if b.plantDelay > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(b.plantDelay):
		}
	}
	end := time.Now()
	b.mu.Lock()
	b.plantWins = append(b.plantWins, timeWindow{url: p.URL, start: start, end: end})
	b.mu.Unlock()
	// Surface extra URLs directly at TierDeferred: they need Detect
	// coverage but were discovered after Plant's batch, so they
	// must NOT re-trigger Plant.
	for _, u := range b.extraURLs {
		core.DiscoverAt(ctx, target.Page(u, ""), core.TierDeferred)
	}
	return nil, nil
}

func (b *barrierTwoPhase) Detect(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	start := time.Now()
	end := time.Now()
	b.mu.Lock()
	b.detectWins = append(b.detectWins, timeWindow{url: p.URL, start: start, end: end})
	b.detectBody = append(b.detectBody, string(p.Body))
	b.mu.Unlock()
	return []core.Finding{{Check: b.name, Title: "stored", Target: p.URL, URL: p.URL}}, nil
}

// TestTwoPhaseFoldCrossTargetBarrier feeds two crawled pages through
// the scanner with a TwoPhaseCheck whose Plant deliberately blocks for
// 30ms. The TierActive -> TierDeferred barrier guarantees every Plant
// across every target completes before any Detect starts. Without the
// barrier (e.g. if TwoPhaseCheck fold-in had been left as a soft
// priority instead of barrier semantics), worker B could pop /b at
// TierDeferred while worker A is still mid-Plant on /a, and the
// windows would overlap.
//
// Two delay knobs catch two different failure shapes:
//   - plantDelay > 0 forces the in-flight window wide enough that
//     scheduler jitter alone is well below the gap.
//   - concurrency=2 ensures two workers exist so a missing barrier
//     could let one fall through to TierDeferred while the other is
//     still in TierActive.
func TestTwoPhaseFoldCrossTargetBarrier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>fresh</body></html>"))
	}))
	defer srv.Close()

	tp := &barrierTwoPhase{
		stubCheck:  stubCheck{name: "barrier-tp"},
		plantDelay: 30 * time.Millisecond,
	}
	s := New(newNilClient(), []core.Check{tp}, WithConcurrency(2))

	pages := make(chan page.Page, 2)
	pages <- page.FromURL(srv.URL + "/a")
	pages <- page.FromURL(srv.URL + "/b")
	close(pages)

	out := make(chan core.Finding, 16)
	if err := s.ScanAll(context.Background(), pages, out); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	for range out {
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()

	if len(tp.plantWins) != 2 {
		t.Fatalf("Plant ran %d times, want 2", len(tp.plantWins))
	}
	if len(tp.detectWins) != 2 {
		t.Fatalf("Detect ran %d times, want 2", len(tp.detectWins))
	}

	var plantMaxEnd time.Time
	for _, w := range tp.plantWins {
		if w.end.After(plantMaxEnd) {
			plantMaxEnd = w.end
		}
	}
	var detectMinStart time.Time
	for _, w := range tp.detectWins {
		if detectMinStart.IsZero() || w.start.Before(detectMinStart) {
			detectMinStart = w.start
		}
	}
	if detectMinStart.Before(plantMaxEnd) {
		t.Errorf("cross-target barrier violated: last Plant ended at %v but first Detect started at %v; TierDeferred must wait for every Plant globally",
			plantMaxEnd, detectMinStart)
	}
}

// TestTwoPhaseFoldDetectSeesFreshBody pins the TierDeferred cache
// invalidation: the seed body was "old" when the producer captured
// it, but Plant fires HTTP traffic that changes server-side state,
// so Detect must run against a freshly-fetched body, not the cached
// one. The fold's worker evicts pageByKey on TierDeferred entry so
// materializePage refetches.
//
// The server flips the body it serves the first time anyone GETs
// /target after the test signals via plantTouched - simulating
// "Plant mutated server state that Detect needs to see."
func TestTwoPhaseFoldDetectSeesFreshBody(t *testing.T) {
	var plantTouched atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if plantTouched.Load() {
			_, _ = w.Write([]byte("<html>POST-PLANT</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>PRE-PLANT</html>"))
	}))
	defer srv.Close()

	tp := &mutatingTwoPhase{
		stubCheck:    stubCheck{name: "mutating-tp"},
		plantTouched: &plantTouched,
	}
	s := New(newNilClient(), []core.Check{tp})

	// Pre-load a seed page with the PRE-PLANT body so the producer
	// path stores it into pageByKey - this is the body the fold would
	// erroneously hand to Detect if it failed to invalidate the cache.
	pre := page.Page{
		URL:     srv.URL + "/target",
		Status:  http.StatusOK,
		Body:    []byte("<html>PRE-PLANT</html>"),
		Fetched: true,
	}
	pages := make(chan page.Page, 1)
	pages <- pre
	close(pages)

	out := make(chan core.Finding, 16)
	if err := s.ScanAll(context.Background(), pages, out); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	for range out {
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()
	if len(tp.detectBodies) != 1 {
		t.Fatalf("Detect ran %d times, want 1", len(tp.detectBodies))
	}
	got := tp.detectBodies[0]
	if !strings.Contains(got, "POST-PLANT") {
		t.Errorf("Detect saw body %q, want POST-PLANT (cache must be invalidated at TierDeferred entry; cached PRE-PLANT body would short-circuit re-fetch)", got)
	}
}

// mutatingTwoPhase flips a server-side flag during Plant so the next
// fetch returns a different body. Lets the test detect whether the
// TierDeferred materialize path actually re-fetches.
type mutatingTwoPhase struct {
	stubCheck
	plantTouched *atomic.Bool

	mu           sync.Mutex
	detectBodies []string
}

func (m *mutatingTwoPhase) Plant(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	m.plantTouched.Store(true)
	return nil, nil
}

func (m *mutatingTwoPhase) DetectURLs() []string { return nil }

func (m *mutatingTwoPhase) Detect(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	m.mu.Lock()
	m.detectBodies = append(m.detectBodies, string(p.Body))
	m.mu.Unlock()
	return nil, nil
}

// TestTwoPhaseFoldSkipsTierDeferredWhenNoTwoPhaseCheck pins the
// scan-wall-clock optimization: a scan with no TwoPhaseCheck must not
// re-push targets at TierDeferred. Otherwise every single-phase scan
// would pay for an extra Pop + scanTier no-op per target.
//
// Verifies by counting fetches against the server with a single-phase
// passive check. Pre-fold, the worker would walk through TierDeferred
// and re-fetch each page; the optimization keeps lastTier=TierActive
// so the page is only fetched once (by the crawler / producer).
func TestTwoPhaseFoldSkipsTierDeferredWhenNoTwoPhaseCheck(t *testing.T) {
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	c := &stubCheck{name: "pure-passive", findings: []core.Finding{{Title: "ok"}}}
	s := New(newNilClient(), []core.Check{c})

	pages := make(chan page.Page, 1)
	pages <- page.FromURL(srv.URL + "/seed")
	close(pages)
	out := make(chan core.Finding, 16)
	if err := s.ScanAll(context.Background(), pages, out); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	for range out {
	}
	// page.FromURL doesn't actually fetch - so the only GETs that
	// could hit the server are from materializePage at a tier where
	// the cache misses. Crawler-origin seeds are cache-hit at every
	// tier ... unless the worker invalidates and re-fetches at
	// TierDeferred. A single-phase scan must NOT do that.
	if got := fetches.Load(); got != 0 {
		t.Errorf("single-phase scan issued %d GETs; want 0 (lastTier should stop at TierActive when no TwoPhaseCheck is registered)", got)
	}
}

// TestTwoPhaseFoldDetectURLsSeededAtTierDeferred pins the
// sync.Once-driven DetectURLs seeding: URLs returned by DetectURLs()
// must be dispatched at TierDeferred (skipping earlier tiers so Plant
// does NOT fire on them - they were discovered after Plant's batch
// finished).
//
// The test feeds a single seed (/seed) plus a DetectURLs entry
// (/discovered). After scan: Plant ran exactly once (on /seed only),
// Detect ran twice (on /seed and on /discovered). Without the fold's
// "skip-to-TierDeferred" semantic, /discovered would walk through
// tiers 1-4 first and Plant would fire on it too.
func TestTwoPhaseFoldDetectURLsSeededAtTierDeferred(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	tp := &barrierTwoPhase{
		stubCheck: stubCheck{name: "detect-urls-tp"},
		extraURLs: []string{srv.URL + "/discovered"},
	}
	s := New(newNilClient(), []core.Check{tp})

	pages := make(chan page.Page, 1)
	pages <- page.FromURL(srv.URL + "/seed")
	close(pages)
	out := make(chan core.Finding, 16)
	if err := s.ScanAll(context.Background(), pages, out); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	for range out {
	}

	tp.mu.Lock()
	defer tp.mu.Unlock()

	if len(tp.plantWins) != 1 {
		var plantedURLs []string
		for _, w := range tp.plantWins {
			plantedURLs = append(plantedURLs, w.url)
		}
		t.Errorf("Plant ran %d times against %v; want 1 (DetectURLs entries must skip earlier tiers - Plant should NOT fire on /discovered)", len(tp.plantWins), plantedURLs)
	}
	if len(tp.detectWins) != 2 {
		t.Fatalf("Detect ran %d times, want 2 (seed + DetectURLs entry)", len(tp.detectWins))
	}
	detectURLs := map[string]bool{}
	for _, w := range tp.detectWins {
		detectURLs[w.url] = true
	}
	if !detectURLs[srv.URL+"/seed"] {
		t.Errorf("Detect missed seed URL; detected URLs: %v", detectURLs)
	}
	if !detectURLs[srv.URL+"/discovered"] {
		t.Errorf("Detect missed DetectURLs entry %q; sync.Once seeding broken", srv.URL+"/discovered")
	}
}

// compile-time sanity: barrierTwoPhase and mutatingTwoPhase satisfy
// core.TwoPhaseCheck so the scanner's type assertion picks them up.
var (
	_ core.TwoPhaseCheck = (*barrierTwoPhase)(nil)
	_ core.TwoPhaseCheck = (*mutatingTwoPhase)(nil)
)
