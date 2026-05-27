package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// crossTierObserver records every Run's start and end timestamp per
// target URL so the cross-target ordering tests can assert that
// every tier-N invocation across all targets completed before any
// tier-(N+1) invocation began. delay parks each call so the
// observation window has real wall-clock overlap potential when the
// dispatch design lacks a barrier.
type crossTierObserver struct {
	name  string
	tier  core.Tier
	kinds []target.Kind
	delay time.Duration

	mu  sync.Mutex
	obs []crossTierObservation
}

type crossTierObservation struct {
	url   string
	start time.Time
	end   time.Time
}

func (o *crossTierObserver) Name() string                 { return o.name }
func (o *crossTierObserver) Level() core.Level            { return core.LevelPassive }
func (o *crossTierObserver) Tier() core.Tier              { return o.tier }
func (o *crossTierObserver) Consumes() []target.Kind      { return o.kinds }
func (o *crossTierObserver) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	start := time.Now()
	if o.delay > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(o.delay):
		}
	}
	end := time.Now()
	o.mu.Lock()
	o.obs = append(o.obs, crossTierObservation{url: p.URL, start: start, end: end})
	o.mu.Unlock()
	return nil, nil
}

// TestCrossTargetTierBarrier feeds three targets to the scanner under
// concurrency=4 and asserts the barrier: every tier-1 (fingerprint)
// observation across the three targets completes BEFORE any tier-2
// (passive) observation starts; same between tier-2 and tier-3;
// between tier-3 and tier-4. Without barrier semantics (e.g. soft
// priority only), worker A could pop /target3@tier2 while worker B
// is still mid tier-1 on /target1, and the windows would overlap.
//
// Each tier's check has a 30ms delay so the in-flight window is wide
// enough to catch any sneaky inversion - scheduler jitter alone is
// well below 30ms.
func TestCrossTargetTierBarrier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	const tierDelay = 30 * time.Millisecond
	fp := &crossTierObserver{name: "fp", tier: core.TierFingerprint, kinds: []target.Kind{target.KindPage}, delay: tierDelay}
	ps := &crossTierObserver{name: "ps", tier: core.TierPassive, kinds: []target.Kind{target.KindPage}, delay: tierDelay}
	ds := &crossTierObserver{name: "ds", tier: core.TierDiscovery, kinds: []target.Kind{target.KindPage}, delay: tierDelay}
	ac := &crossTierObserver{name: "ac", tier: core.TierActive, kinds: []target.Kind{target.KindPage}, delay: tierDelay}

	s := New(newNilClient(), []core.Check{fp, ps, ds, ac}, WithConcurrency(4))

	pages := make(chan page.Page, 3)
	for _, p := range []string{"/a", "/b", "/c"} {
		pages <- page.FromURL(srv.URL + p)
	}
	close(pages)

	out := make(chan core.Finding, 16)
	errCh := make(chan error, 1)
	go func() { errCh <- s.ScanAll(context.Background(), pages, out) }()
	for range out {
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	// Each tier observer should have seen all three targets.
	for _, ob := range []*crossTierObserver{fp, ps, ds, ac} {
		ob.mu.Lock()
		got := len(ob.obs)
		ob.mu.Unlock()
		if got != 3 {
			t.Fatalf("tier %s saw %d targets, want 3 (one per registered page)", ob.name, got)
		}
	}

	// Assert the barrier: max(end) of tier N <= min(start) of tier N+1.
	tiers := []*crossTierObserver{fp, ps, ds, ac}
	for i := 0; i < len(tiers)-1; i++ {
		lower, upper := tiers[i], tiers[i+1]
		lowerMaxEnd := tierMaxEnd(lower)
		upperMinStart := tierMinStart(upper)
		if upperMinStart.Before(lowerMaxEnd) {
			t.Errorf("cross-target barrier violated: tier %s last-completion = %v but tier %s first-start = %v (any %s observation must finish before any %s observation begins)",
				lower.name, lowerMaxEnd, upper.name, upperMinStart, lower.name, upper.name)
		}
	}
}

func tierMaxEnd(o *crossTierObserver) time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	var t time.Time
	for _, ob := range o.obs {
		if ob.end.After(t) {
			t = ob.end
		}
	}
	return t
}

func tierMinStart(o *crossTierObserver) time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	var t time.Time
	for _, ob := range o.obs {
		if t.IsZero() || ob.start.Before(t) {
			t = ob.start
		}
	}
	return t
}

// TestDiscoveryReEntersAtLowestTier confirms that a discovery emitted
// by a TierActive check produces a new target which is dispatched
// starting at TierFingerprint (not TierActive). Concretely: emitter
// is a TierActive check on /seed; it emits target.Page for
// /discovered. The downstream fingerprint observer is a tier-1 check
// that should see /discovered. If the dispatcher had pushed the
// discovery at the emitter's tier, the tier-1 observer would never
// fire against /discovered.
func TestDiscoveryReEntersAtLowestTier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	emit := &activeEmittingPageCheck{
		name: "emit-active",
		emit: target.Page(srv.URL+"/discovered", ""),
	}
	fpObs := &crossTierObserver{name: "fp", tier: core.TierFingerprint, kinds: []target.Kind{target.KindPage}}

	s := New(newNilClient(), []core.Check{emit, fpObs}, WithConcurrency(2))
	if _, err := runOne(context.Background(), s, srv.URL+"/seed"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	fpObs.mu.Lock()
	defer fpObs.mu.Unlock()
	var sawDiscovered bool
	for _, ob := range fpObs.obs {
		if ob.url == srv.URL+"/discovered" {
			sawDiscovered = true
			break
		}
	}
	if !sawDiscovered {
		var seenURLs []string
		for _, ob := range fpObs.obs {
			seenURLs = append(seenURLs, ob.url)
		}
		t.Errorf("TierFingerprint observer did not see /discovered; saw URLs %v. Discoveries must re-enter the queue at TierFingerprint so freshly-surfaced targets get every tier of coverage.", seenURLs)
	}
}

// activeEmittingPageCheck is a TierActive-tier check that emits one
// KindPage discovery per Run. Distinct from the existing emittingCheck
// helper because here we explicitly declare TierActive to prove
// discoveries from an active emitter re-enter at TierFingerprint, not
// at the emitter's tier.
type activeEmittingPageCheck struct {
	name string
	emit target.Target
	runs atomic.Int64
}

func (e *activeEmittingPageCheck) Name() string                 { return e.name }
func (e *activeEmittingPageCheck) Level() core.Level            { return core.LevelPassive }
func (e *activeEmittingPageCheck) Tier() core.Tier              { return core.TierActive }
func (e *activeEmittingPageCheck) Consumes() []target.Kind      { return []target.Kind{target.KindPage} }
func (e *activeEmittingPageCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	e.runs.Add(1)
	core.Discover(ctx, e.emit)
	return nil, nil
}
