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

// emittingCheck calls core.Discover on every Run, with a configurable
// target. Used to drive the discovery round-trip and self-loop tests:
// the emitter's runs counter exposes whether the self-loop break kept
// the check from re-firing on its own emission.
type emittingCheck struct {
	name    string
	emit    target.Target
	runs    atomic.Int64
	seenURL sync.Map // string -> struct{}
}

func (e *emittingCheck) Name() string      { return e.name }
func (e *emittingCheck) Level() core.Level { return core.LevelPassive }
func (e *emittingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	e.runs.Add(1)
	e.seenURL.Store(p.URL, struct{}{})
	if e.emit.URL != "" {
		core.Discover(ctx, e.emit)
	}
	return nil, nil
}

// recordingCheck just records every URL it is dispatched against.
// Used opposite emittingCheck to confirm a discovery actually round-
// trips through the worklist to a downstream check.
type recordingCheck struct {
	name    string
	runs    atomic.Int64
	seenURL sync.Map // string -> struct{}
}

func (o *recordingCheck) Name() string      { return o.name }
func (o *recordingCheck) Level() core.Level { return core.LevelPassive }
func (o *recordingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	o.runs.Add(1)
	o.seenURL.Store(p.URL, struct{}{})
	return nil, nil
}

// targetedCheck wraps stubCheck with a core.Targeted declaration so
// it only receives dispatch for a configured set of target Kinds.
// Used to exercise the consumesKind dispatch filter.
type targetedCheck struct {
	stubCheck
	tier  core.Tier
	kinds []target.Kind
}

func (t *targetedCheck) Tier() core.Tier            { return t.tier }
func (t *targetedCheck) Consumes() []target.Kind    { return t.kinds }

func TestDiscoveryRoundTripThroughWorklist(t *testing.T) {
	// Two-URL site: / responds with HTML; /discovered also responds.
	// Workers materialize the discovery-origin /discovered URL via
	// the fetch path and dispatch observers against it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	emit := &emittingCheck{
		name: "emit",
		emit: target.Page(srv.URL+"/discovered", ""),
	}
	observe := &recordingCheck{name: "observe"}

	s := New(newNilClient(), []core.Check{emit, observe})

	got, err := runOne(context.Background(), s, srv.URL+"/")
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no findings (stubs emit none), got %d: %+v", len(got), got)
	}

	if observe.runs.Load() != 2 {
		t.Errorf("recordingCheck runs = %d, want 2 (initial + discovered)", observe.runs.Load())
	}
	if _, seen := observe.seenURL.Load(srv.URL + "/discovered"); !seen {
		t.Errorf("recordingCheck never received the discovery; seen URLs: %s", dumpMap(&observe.seenURL))
	}
}

func TestDiscoverySelfLoopBreak(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	// The emitter's discovery (Origin = "check:emit", auto-tagged by
	// the scanner's per-check discoverer) should NOT be re-dispatched
	// to itself when the worker pulls the new target.
	emit := &emittingCheck{
		name: "emit",
		emit: target.Page(srv.URL+"/discovered", ""),
	}

	s := New(newNilClient(), []core.Check{emit})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	if emit.runs.Load() != 1 {
		t.Errorf("emittingCheck runs = %d, want 1 (self-loop break must skip the check against its own emission)", emit.runs.Load())
	}
	// The /discovered target IS pulled and materialized; the check
	// is just skipped against it. Verify the emitter only saw the
	// initial URL.
	if _, seen := emit.seenURL.Load(srv.URL + "/discovered"); seen {
		t.Errorf("emittingCheck must not have received its own emission")
	}
}

func TestDiscoveryKindFilterRejectsMismatch(t *testing.T) {
	// A check declaring Consumes = []Kind{KindEndpoint} must NOT
	// receive dispatch for KindPage targets (the crawler's default).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	endpointOnly := &targetedCheck{
		stubCheck: stubCheck{name: "endpoint-only"},
		tier:      core.TierActive,
		kinds:     []target.Kind{target.KindEndpoint},
	}
	pageDefault := &recordingCheck{name: "page-default"}

	s := New(newNilClient(), []core.Check{endpointOnly, pageDefault})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	if endpointOnly.hits.Load() != 0 {
		t.Errorf("endpoint-only check hits = %d, want 0 (KindPage must not match Consumes=KindEndpoint)", endpointOnly.hits.Load())
	}
	if pageDefault.runs.Load() != 1 {
		t.Errorf("page-default check runs = %d, want 1", pageDefault.runs.Load())
	}
}

func TestDiscoveryKindFilterDefaultIsKindPage(t *testing.T) {
	// A check that does NOT implement core.Targeted defaults to
	// KindPage-only dispatch. The pre-worklist catalog runs entirely
	// on this default; the test asserts the default still fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &recordingCheck{name: "untargeted"}
	s := New(newNilClient(), []core.Check{c})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if c.runs.Load() != 1 {
		t.Errorf("untargeted check runs = %d, want 1 (default Consumes is KindPage)", c.runs.Load())
	}
}

func TestDiscoveryHostBudgetCaps(t *testing.T) {
	// Emit five discoveries from the initial page; the host budget
	// caps total per-host pushes at 2 (the initial page itself plus
	// one discovery), so only one discovery should reach observers.
	//
	// Each emission targets a unique path so dedupe does not collapse
	// them. The httptest server returns 200 for everything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	emit := &emittingMultiCheck{
		name: "emit-many",
		urls: []string{
			srv.URL + "/a",
			srv.URL + "/b",
			srv.URL + "/c",
			srv.URL + "/d",
			srv.URL + "/e",
		},
	}
	observe := &recordingCheck{name: "observe"}

	s := New(newNilClient(), []core.Check{emit, observe}, WithHostBudget(2))

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	// observe should run on at most 2 targets total (the crawler's
	// initial page plus at most one discovery), but the exact second
	// target depends on scheduling: the test asserts the upper bound
	// rather than a specific URL set.
	if got := observe.runs.Load(); got > 2 {
		t.Errorf("recordingCheck runs = %d, want at most 2 (host budget)", got)
	}
	if got := observe.runs.Load(); got < 1 {
		t.Errorf("recordingCheck runs = %d, want at least 1 (initial page must dispatch)", got)
	}
}

// emittingMultiCheck calls core.Discover with each URL in urls on
// every Run. Used to drive the host-budget test where the emitter
// pushes more targets than the budget allows.
type emittingMultiCheck struct {
	name string
	urls []string
}

func (e *emittingMultiCheck) Name() string      { return e.name }
func (e *emittingMultiCheck) Level() core.Level { return core.LevelPassive }
func (e *emittingMultiCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	for _, u := range e.urls {
		core.Discover(ctx, target.Page(u, ""))
	}
	return nil, nil
}

func TestDiscoveryFetchErrorDoesNotPin(t *testing.T) {
	// Emit a discovery for a URL that connects-refused immediately.
	// The worker's materializePage should report the error via
	// onError and move on; the observing check should still run
	// against the initial crawler-origin page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// http://127.0.0.1:1 should refuse connections - any well-known
	// unused port works, but :1 is the canonical "definitely not
	// listening" choice.
	emit := &emittingCheck{
		name: "emit",
		emit: target.Page("http://127.0.0.1:1/", ""),
	}
	observe := &recordingCheck{name: "observe"}

	var errs atomic.Int64
	s := New(newNilClient(), []core.Check{emit, observe},
		WithErrorHandler(func(target, check string, err error) { errs.Add(1) }),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := runOne(ctx, s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if observe.runs.Load() < 1 {
		t.Errorf("recordingCheck runs = %d, want >= 1 (initial page must still dispatch)", observe.runs.Load())
	}
	if errs.Load() < 1 {
		t.Errorf("onError calls = %d, want >= 1 (discovery-fetch failure should report)", errs.Load())
	}
}

// dumpMap turns a sync.Map of strings into a stable comma-separated
// list for test diagnostics.
func dumpMap(m *sync.Map) string {
	var keys []string
	m.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
		return true
	})
	if len(keys) == 0 {
		return "(empty)"
	}
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += k
	}
	return out
}
