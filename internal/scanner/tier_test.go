package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
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

// tierRecorder is a check that records its own start / end timestamps
// each time Run fires. Used by the tier-ordering test to assert that
// every fingerprint-tier observation completes before any passive-tier
// observation begins, and so on through discovery and active.
//
// The delay field forces real wall-clock overlap inside a tier so the
// parallelism assertion (within-tier checks overlap) is not racing
// against scheduler jitter.
type tierRecorder struct {
	name  string
	tier  core.Tier
	kinds []target.Kind
	delay time.Duration

	mu    sync.Mutex
	start time.Time
	end   time.Time
	runs  atomic.Int64
}

func (r *tierRecorder) Name() string                 { return r.name }
func (r *tierRecorder) Level() core.Level            { return core.LevelPassive }
func (r *tierRecorder) Tier() core.Tier              { return r.tier }
func (r *tierRecorder) Consumes() []target.Kind      { return r.kinds }
func (r *tierRecorder) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	r.mu.Lock()
	r.start = time.Now()
	r.mu.Unlock()
	if r.delay > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(r.delay):
		}
	}
	r.mu.Lock()
	r.end = time.Now()
	r.mu.Unlock()
	r.runs.Add(1)
	return nil, nil
}

func (r *tierRecorder) window() (time.Time, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.start, r.end
}

// newTierServer returns an httptest server that serves a trivial HTML
// body on every path. The tier tests do not assert on the response;
// they only need a real URL to drive runOne through ScanAll.
func newTierServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestScanOneTierOrdering registers one recorder per tier and confirms
// the scanner drains every tier completely before starting the next.
// The assertion is end[i] <= start[i+1] - any overlap across tiers
// (e.g. a passive check starting while a fingerprint check is still
// running) would indicate the tier loop is dispatching concurrently
// rather than sequentially.
func TestScanOneTierOrdering(t *testing.T) {
	const tierDelay = 30 * time.Millisecond
	srv := newTierServer(t)

	fp := &tierRecorder{name: "fp", tier: core.TierFingerprint, kinds: []target.Kind{target.KindPage}, delay: tierDelay}
	ps := &tierRecorder{name: "ps", tier: core.TierPassive, kinds: []target.Kind{target.KindPage}, delay: tierDelay}
	ds := &tierRecorder{name: "ds", tier: core.TierDiscovery, kinds: []target.Kind{target.KindPage}, delay: tierDelay}
	ac := &tierRecorder{name: "ac", tier: core.TierActive, kinds: []target.Kind{target.KindPage}, delay: tierDelay}

	s := New(newNilClient(), []core.Check{ac, ds, ps, fp}) // deliberately reverse order
	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	type pair struct {
		name  string
		start time.Time
		end   time.Time
	}
	got := make([]pair, 0, 4)
	for _, r := range []*tierRecorder{fp, ps, ds, ac} {
		if r.runs.Load() != 1 {
			t.Fatalf("%s ran %d times, want 1", r.name, r.runs.Load())
		}
		st, en := r.window()
		got = append(got, pair{r.name, st, en})
	}

	for i := 0; i < len(got)-1; i++ {
		cur, next := got[i], got[i+1]
		if !cur.end.Before(next.start) && !cur.end.Equal(next.start) {
			t.Errorf("%s ended at %v but %s started at %v: tiers must drain in order",
				cur.name, cur.end, next.name, next.start)
		}
	}
}

// TestScanOneTierParallelismWithinTier registers two checks at the
// same tier with overlapping delays; their run windows must overlap.
// If the tier loop accidentally serialized everything (e.g. via a
// per-tier sem of size 1) the windows would be sequential and this
// test catches that.
func TestScanOneTierParallelismWithinTier(t *testing.T) {
	const delay = 50 * time.Millisecond
	srv := newTierServer(t)

	a := &tierRecorder{name: "a", tier: core.TierPassive, kinds: []target.Kind{target.KindPage}, delay: delay}
	b := &tierRecorder{name: "b", tier: core.TierPassive, kinds: []target.Kind{target.KindPage}, delay: delay}

	s := New(newNilClient(), []core.Check{a, b})
	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	aStart, aEnd := a.window()
	bStart, bEnd := b.window()

	overlap := !aEnd.Before(bStart) && !bEnd.Before(aStart)
	if !overlap {
		t.Errorf("same-tier checks did not overlap: a=[%v,%v] b=[%v,%v]; want concurrent dispatch within a tier",
			aStart, aEnd, bStart, bEnd)
	}
}

// TestScanOneCheckTierDefaultsToActive registers a Targeted-free check
// alongside an explicit fingerprint-tier check; the un-Targeted one
// must run after the fingerprint one (because un-Targeted defaults to
// TierActive, which drains last).
func TestScanOneCheckTierDefaultsToActive(t *testing.T) {
	srv := newTierServer(t)

	fp := &tierRecorder{name: "fp", tier: core.TierFingerprint, kinds: []target.Kind{target.KindPage}, delay: 20 * time.Millisecond}
	plain := &stubCheck{name: "plain"} // no Targeted, no Tier - defaults to TierActive

	plainStart := make(chan time.Time, 1)
	plainObserved := &observingStub{stubCheck: plain, started: plainStart}

	s := New(newNilClient(), []core.Check{plainObserved, fp})
	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	_, fpEnd := fp.window()
	select {
	case st := <-plainStart:
		if st.Before(fpEnd) {
			t.Errorf("Targeted-free check started at %v before fingerprint-tier check ended at %v; default tier must be TierActive (drains last)",
				st, fpEnd)
		}
	default:
		t.Fatalf("default-tier check never started; runs=%d", plainObserved.hits.Load())
	}
}

// observingStub wraps stubCheck to capture the moment Run begins, used
// by the default-tier test to compare against a fingerprint-tier
// recorder's end time. Embedded so it inherits Name/Level/Run from
// stubCheck; intentionally does NOT implement Targeted.
type observingStub struct {
	*stubCheck
	started chan<- time.Time
}

func (o *observingStub) Run(ctx context.Context, c *httpclient.Client, sc *scope.Scope, p page.Page) ([]core.Finding, error) {
	select {
	case o.started <- time.Now():
	default:
	}
	return o.stubCheck.Run(ctx, c, sc, p)
}

// TestScanOneTierOrderingPreservedAcrossPermutations runs the same
// fingerprint/passive/discovery/active recorder set across every
// permutation of registration order and confirms the dispatch order
// is dictated by the tier, not by the slice ordering the caller
// happened to pass to New. Pin against accidental reliance on
// registration order.
func TestScanOneTierOrderingPreservedAcrossPermutations(t *testing.T) {
	srv := newTierServer(t)

	build := func() (*tierRecorder, *tierRecorder, *tierRecorder, *tierRecorder) {
		return &tierRecorder{name: "fp", tier: core.TierFingerprint, kinds: []target.Kind{target.KindPage}, delay: 10 * time.Millisecond},
			&tierRecorder{name: "ps", tier: core.TierPassive, kinds: []target.Kind{target.KindPage}, delay: 10 * time.Millisecond},
			&tierRecorder{name: "ds", tier: core.TierDiscovery, kinds: []target.Kind{target.KindPage}, delay: 10 * time.Millisecond},
			&tierRecorder{name: "ac", tier: core.TierActive, kinds: []target.Kind{target.KindPage}, delay: 10 * time.Millisecond}
	}

	// A small set of permutations - exhaustive is 24, but the cost
	// per case is real wall-clock so the smoke set focuses on
	// "reversed", "interleaved", and "active first".
	perms := [][4]int{
		{0, 1, 2, 3}, // canonical
		{3, 2, 1, 0}, // reversed
		{3, 0, 2, 1}, // interleaved
		{1, 3, 0, 2}, // arbitrary
	}
	for _, perm := range perms {
		fp, ps, ds, ac := build()
		all := []core.Check{fp, ps, ds, ac}
		ordered := []core.Check{all[perm[0]], all[perm[1]], all[perm[2]], all[perm[3]]}
		s := New(newNilClient(), ordered)
		if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
			t.Fatalf("perm %v: ScanAll: %v", perm, err)
		}
		rs := []*tierRecorder{fp, ps, ds, ac}
		sort.Slice(rs, func(i, j int) bool {
			si, _ := rs[i].window()
			sj, _ := rs[j].window()
			return si.Before(sj)
		})
		for i, want := range []string{"fp", "ps", "ds", "ac"} {
			if rs[i].name != want {
				t.Errorf("perm %v: dispatch position %d = %q, want %q (tier order must dominate registration order)",
					perm, i, rs[i].name, want)
			}
		}
	}
}
