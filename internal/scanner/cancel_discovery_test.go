package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// gatedTieredCheck is a Targeted check that closes `started` once Run
// enters and then blocks on `release` until the test signals it to
// return. Used to park scanOne mid-tier so the test can cancel ctx and
// verify the tier loop's behavior on the in-flight + post-cancel tiers.
type gatedTieredCheck struct {
	name     string
	tier     core.Tier
	kinds    []target.Kind
	started  chan struct{}
	release  chan struct{}
	findings []core.Finding
	runs     atomic.Int64
}

func (g *gatedTieredCheck) Name() string                 { return g.name }
func (g *gatedTieredCheck) Level() core.Level            { return core.LevelPassive }
func (g *gatedTieredCheck) Tier() core.Tier              { return g.tier }
func (g *gatedTieredCheck) Consumes() []target.Kind      { return g.kinds }
func (g *gatedTieredCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	g.runs.Add(1)
	close(g.started)
	select {
	case <-g.release:
	case <-time.After(5 * time.Second):
	}
	return g.findings, nil
}

// emittingThenGated emits a discovery and then blocks on `release`.
// Intentionally does NOT implement core.Targeted, so it dispatches at
// the default TierActive alongside the recordingCheck consumer the
// cancel test pairs it with - same tier means within-tier parallelism
// fires both against the seed before the emitter parks.
type emittingThenGated struct {
	name    string
	emit    target.Target
	started chan struct{}
	release chan struct{}
	runs    atomic.Int64
}

func (e *emittingThenGated) Name() string      { return e.name }
func (e *emittingThenGated) Level() core.Level { return core.LevelPassive }
func (e *emittingThenGated) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	e.runs.Add(1)
	core.Discover(ctx, e.emit)
	close(e.started)
	select {
	case <-e.release:
	case <-time.After(5 * time.Second):
	}
	return []core.Finding{{Check: e.name, Title: "in-flight flush"}}, nil
}

// TestScanCancelMidTierStopsSubsequentTiers parks scanOne inside the
// passive tier, cancels ctx, and asserts:
//   - tier 1 (fingerprint) completed before cancel - it ran exactly once
//   - tier 2 (passive)'s in-flight finding flushes to out (cancellation
//     contract: scanOne's send loop does not select on ctx.Done)
//   - tier 3 (discovery) and tier 4 (active) NEVER ran (the tier loop's
//     ctx.Err() check skipped them)
//   - ScanAll returns context.Canceled
//
// Pins the tier loop's cancel-between-tiers behavior: a future change
// that accidentally ran every tier in parallel, or that flushed all
// tiers before checking ctx, would fail this.
func TestScanCancelMidTierStopsSubsequentTiers(t *testing.T) {
	srv := newTierServer(t)

	fp := &tierRecorder{name: "fp", tier: core.TierFingerprint, kinds: []target.Kind{target.KindPage}}
	ps := &gatedTieredCheck{
		name:     "ps",
		tier:     core.TierPassive,
		kinds:    []target.Kind{target.KindPage},
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		findings: []core.Finding{{Check: "ps", Title: "passive-flush"}},
	}
	ds := &tierRecorder{name: "ds", tier: core.TierDiscovery, kinds: []target.Kind{target.KindPage}}
	ac := &tierRecorder{name: "ac", tier: core.TierActive, kinds: []target.Kind{target.KindPage}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := New(newNilClient(), []core.Check{fp, ps, ds, ac}, WithConcurrency(1))

	pages := make(chan page.Page, 1)
	pages <- page.FromURL(srv.URL + "/")
	close(pages)

	out := make(chan core.Finding, 16)
	scanDone := make(chan error, 1)
	go func() { scanDone <- s.ScanAll(ctx, pages, out) }()

	<-ps.started
	cancel()
	close(ps.release)

	var got []core.Finding
	for f := range out {
		got = append(got, f)
	}
	if err := <-scanDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanAll err = %v, want context.Canceled", err)
	}

	if len(got) != 1 || got[0].Title != "passive-flush" {
		t.Fatalf("findings = %+v, want one passive-flush (in-flight tier-2 finding must flush after cancel)", got)
	}
	if fp.runs.Load() != 1 {
		t.Errorf("fingerprint runs = %d, want 1 (tier 1 must complete before cancel reaches tier 2)", fp.runs.Load())
	}
	if ds.runs.Load() != 0 {
		t.Errorf("discovery runs = %d, want 0 (tier 3 must be skipped on ctx cancel)", ds.runs.Load())
	}
	if ac.runs.Load() != 0 {
		t.Errorf("active runs = %d, want 0 (tier 4 must be skipped on ctx cancel)", ac.runs.Load())
	}
}

// TestScanCancelDropsQueuedDiscoveries puts a discovery into the
// worklist via an in-flight check, cancels ctx while that check is
// still parked, and asserts the worker never dispatches the queued
// discovery: the consumer's run count covers the seed only.
//
// Pins the worker-loop cancel behavior on the worklist: Pop must
// short-circuit ctx.Err() before handing out queued items so cancel
// is honored even when the queue still has work.
func TestScanCancelDropsQueuedDiscoveries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	emit := &emittingThenGated{
		name:    "emit",
		emit:    target.Page(srv.URL+"/discovered", ""),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	observe := &recordingCheck{name: "observe"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := New(newNilClient(), []core.Check{emit, observe}, WithConcurrency(1))

	pages := make(chan page.Page, 1)
	pages <- page.FromURL(srv.URL + "/")
	close(pages)

	out := make(chan core.Finding, 16)
	scanDone := make(chan error, 1)
	go func() { scanDone <- s.ScanAll(ctx, pages, out) }()

	<-emit.started
	cancel()
	close(emit.release)

	var got []core.Finding
	for f := range out {
		got = append(got, f)
	}
	if err := <-scanDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanAll err = %v, want context.Canceled", err)
	}

	if len(got) != 1 || got[0].Title != "in-flight flush" {
		t.Fatalf("findings = %+v, want one in-flight flush", got)
	}
	if observe.runs.Load() != 1 {
		t.Errorf("recordingCheck runs = %d, want 1 (seed only; queued discovery must not be popped after cancel)", observe.runs.Load())
	}
	if _, seenDiscovered := observe.seenURL.Load(srv.URL + "/discovered"); seenDiscovered {
		t.Errorf("recordingCheck saw /discovered; queued discovery should not have dispatched after cancel")
	}
}

// TestScanCancelDoesNotBlockDiscoveryEmission confirms a check that
// calls core.Discover after ctx has cancelled does not hang on the
// Push call. The worklist's Push checks ctx.Err() first and returns
// false immediately; this test pins that contract end-to-end so a
// future change that, for example, made Push synchronously block on
// a full queue or a closed cond would fail here.
func TestScanCancelDoesNotBlockDiscoveryEmission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	const burst = 200
	var emitted atomic.Int64
	burstCheck := &postCancelBurstEmitter{
		name:     "burst",
		baseURL:  srv.URL,
		emitN:    burst,
		emitted:  &emitted,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		findings: []core.Finding{{Check: "burst", Title: "burst-flush"}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := New(newNilClient(), []core.Check{burstCheck}, WithConcurrency(1))

	pages := make(chan page.Page, 1)
	pages <- page.FromURL(srv.URL + "/")
	close(pages)

	out := make(chan core.Finding, 16)
	scanDone := make(chan error, 1)
	go func() { scanDone <- s.ScanAll(ctx, pages, out) }()

	<-burstCheck.started
	cancel()
	close(burstCheck.release)

	emitDone := make(chan struct{})
	go func() {
		for range out {
		}
		close(emitDone)
	}()
	select {
	case <-emitDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("ScanAll did not drain within 3s; post-cancel Discover calls likely blocked the emitter")
	}
	if err := <-scanDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("ScanAll err = %v, want context.Canceled", err)
	}
	if emitted.Load() != burst {
		t.Errorf("post-cancel Discover calls completed = %d, want %d (every Push must return promptly even after cancel)", emitted.Load(), burst)
	}
}

// postCancelBurstEmitter signals started, waits for release (which
// the test closes AFTER cancelling ctx), then fires emitN Discover
// calls in a tight loop. Each call must return immediately because
// the worklist's Push sees ctx.Err() and returns false; if Push ever
// blocked, emitted would not reach emitN within the test's deadline.
type postCancelBurstEmitter struct {
	name     string
	baseURL  string
	emitN    int
	emitted  *atomic.Int64
	started  chan struct{}
	release  chan struct{}
	findings []core.Finding
}

func (b *postCancelBurstEmitter) Name() string      { return b.name }
func (b *postCancelBurstEmitter) Level() core.Level { return core.LevelPassive }
func (b *postCancelBurstEmitter) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	close(b.started)
	select {
	case <-b.release:
	case <-time.After(5 * time.Second):
	}
	for i := 0; i < b.emitN; i++ {
		core.Discover(ctx, target.Page(b.baseURL+"/d"+strconv.Itoa(i), ""))
		b.emitted.Add(1)
	}
	return b.findings, nil
}
