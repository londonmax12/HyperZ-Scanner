package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// paramEmittingCheck emits one KindParam discovery per Run, naming
// a parameter and its location on a parent URL. Used to drive the
// param-materialization round-trip test.
type paramEmittingCheck struct {
	name     string
	url      string
	param    string
	location string
}

func (e *paramEmittingCheck) Name() string      { return e.name }
func (e *paramEmittingCheck) Level() core.Level { return core.LevelPassive }
func (e *paramEmittingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	core.Discover(ctx, target.Param(e.url, e.param, e.location, ""))
	return nil, nil
}

// paramConsumingCheck declares Consumes = KindParam and records both
// the Target metadata it sees via TargetFrom and the page.Page body
// it received via the dispatch (used to assert the worker actually
// fetched the parent URL when materializing a discovery-origin
// KindParam).
type paramConsumingCheck struct {
	name      string
	mu        sync.Mutex
	seenT     []target.Target
	seenBody  []string
	seenURL   []string
	seenForms []int // form count per dispatch
}

func (e *paramConsumingCheck) Name() string                 { return e.name }
func (e *paramConsumingCheck) Level() core.Level            { return core.LevelPassive }
func (e *paramConsumingCheck) Tier() core.Tier              { return core.TierActive }
func (e *paramConsumingCheck) Consumes() []target.Kind      { return []target.Kind{target.KindParam} }
func (e *paramConsumingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	e.mu.Lock()
	e.seenT = append(e.seenT, core.TargetFrom(ctx))
	e.seenBody = append(e.seenBody, string(p.Body))
	e.seenURL = append(e.seenURL, p.URL)
	e.seenForms = append(e.seenForms, len(p.Forms))
	e.mu.Unlock()
	return nil, nil
}

func TestParamDiscoveryRoundTrip(t *testing.T) {
	// The parent URL responds with a marker body so we can assert
	// the worker actually fetched it during materialization (rather
	// than handing the consumer an empty page.Page like the
	// KindEndpoint path does).
	const parentMarker = "PARENT-PAGE-MARKER-XYZ"
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			fetches.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>" + parentMarker + "</body></html>"))
	}))
	defer srv.Close()

	emit := &paramEmittingCheck{
		name:     "emit-param",
		url:      srv.URL + "/redirect",
		param:    "next",
		location: "query",
	}
	consume := &paramConsumingCheck{name: "consume-param"}

	s := New(newNilClient(), []core.Check{emit, consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seenT) != 1 {
		t.Fatalf("param consumer Run count = %d, want 1; seen URLs: %v", len(consume.seenT), consume.seenURL)
	}
	got := consume.seenT[0]
	if got.Kind != target.KindParam {
		t.Errorf("dispatched target Kind = %v, want KindParam", got.Kind)
	}
	if got.Param != "next" {
		t.Errorf("dispatched target Param = %q, want next", got.Param)
	}
	if got.ParamLocation != "query" {
		t.Errorf("dispatched target ParamLocation = %q, want query", got.ParamLocation)
	}
	if got.URL != srv.URL+"/redirect" {
		t.Errorf("dispatched target URL = %q, want %s/redirect", got.URL, srv.URL)
	}
	if got.Origin != "check:emit-param" {
		t.Errorf("dispatched target Origin = %q, want check:emit-param", got.Origin)
	}

	// The worker must have fetched /redirect during materialization so
	// the consumer sees the parent body (forms, baseline response).
	if fetches.Load() != 1 {
		t.Errorf("worker fetched parent URL %d times, want 1", fetches.Load())
	}
	if got, want := consume.seenBody[0], parentMarker; !strings.Contains(got, want) {
		t.Errorf("consumer body did not include parent marker; got %q", got)
	}
}

func TestParamConsumerNotDispatchedAgainstKindPage(t *testing.T) {
	// A check declaring Consumes = KindParam must NOT receive the
	// crawler's KindPage seed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	consume := &paramConsumingCheck{name: "consume-only"}

	s := New(newNilClient(), []core.Check{consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seenT) != 0 {
		t.Errorf("param consumer ran %d times against crawler KindPage; want 0", len(consume.seenT))
	}
}


