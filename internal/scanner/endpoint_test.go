package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
	"github.com/londonmax12/hyperz/internal/target"
)

// endpointEmittingCheck emits one KindEndpoint discovery per Run. Used
// to drive the endpoint-materialization round-trip test: an upstream
// check surfaces a /api/login POST target, the worker hands it to a
// downstream check, the downstream reads Method + ContentType via
// core.TargetFrom.
type endpointEmittingCheck struct {
	name        string
	endpointURL string
	method      string
	contentType string
}

func (e *endpointEmittingCheck) Name() string      { return e.name }
func (e *endpointEmittingCheck) Level() core.Level { return core.LevelPassive }
func (e *endpointEmittingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	core.Discover(ctx, target.Endpoint(e.endpointURL, e.method, e.contentType, ""))
	return nil, nil
}

// endpointConsumingCheck declares Consumes = KindEndpoint so it
// receives only endpoint dispatches. On each Run it captures the
// target.Target from ctx so the test can assert the Method and
// ContentType made it through.
type endpointConsumingCheck struct {
	name    string
	mu      sync.Mutex
	seen    []target.Target
	seenURL []string
}

func (e *endpointConsumingCheck) Name() string                 { return e.name }
func (e *endpointConsumingCheck) Level() core.Level            { return core.LevelPassive }
func (e *endpointConsumingCheck) Tier() core.Tier              { return core.TierActive }
func (e *endpointConsumingCheck) Consumes() []target.Kind      { return []target.Kind{target.KindEndpoint} }
func (e *endpointConsumingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	e.mu.Lock()
	e.seen = append(e.seen, core.TargetFrom(ctx))
	e.seenURL = append(e.seenURL, p.URL)
	e.mu.Unlock()
	return nil, nil
}

func TestEndpointDiscoveryRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	emit := &endpointEmittingCheck{
		name:        "emit-endpoint",
		endpointURL: srv.URL + "/api/login",
		method:      "POST",
		contentType: "application/json",
	}
	consume := &endpointConsumingCheck{name: "consume-endpoint"}

	s := New(newNilClient(), []core.Check{emit, consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seen) != 1 {
		t.Fatalf("endpoint consumer Run count = %d, want 1 (one endpoint emission); seen URLs: %v", len(consume.seen), consume.seenURL)
	}
	got := consume.seen[0]
	if got.Kind != target.KindEndpoint {
		t.Errorf("dispatched target Kind = %v, want KindEndpoint", got.Kind)
	}
	if got.URL != srv.URL+"/api/login" {
		t.Errorf("dispatched target URL = %q, want %q", got.URL, srv.URL+"/api/login")
	}
	if got.Method != "POST" {
		t.Errorf("dispatched target Method = %q, want POST (uppercased by Endpoint constructor)", got.Method)
	}
	if got.ContentType != "application/json" {
		t.Errorf("dispatched target ContentType = %q, want application/json", got.ContentType)
	}
	if got.Origin != "check:emit-endpoint" {
		t.Errorf("dispatched target Origin = %q, want check:emit-endpoint (scanner-tagged)", got.Origin)
	}
}

func TestEndpointMaterializationDoesNotFetch(t *testing.T) {
	// If the worker were issuing the declared method (POST) against
	// the endpoint URL, this server would log the hit. The
	// materialization path for KindEndpoint must NOT fetch - the
	// method may be destructive and the operator has not authorized
	// the worker to invoke it on its own.
	var hits int
	var hitsMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/destructive" {
			hitsMu.Lock()
			hits++
			hitsMu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	emit := &endpointEmittingCheck{
		name:        "emit-destructive",
		endpointURL: srv.URL + "/api/destructive",
		method:      "DELETE",
		contentType: "",
	}
	consume := &endpointConsumingCheck{name: "consume-destructive"}

	s := New(newNilClient(), []core.Check{emit, consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	hitsMu.Lock()
	defer hitsMu.Unlock()
	if hits != 0 {
		t.Errorf("worker issued %d requests to /api/destructive; want 0 (KindEndpoint must not be fetched)", hits)
	}
	// The downstream check still dispatched, so it saw the Target.
	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seen) != 1 {
		t.Errorf("downstream consumer should still have dispatched; got %d runs", len(consume.seen))
	}
}

func TestEndpointConsumerNotDispatchedAgainstKindPage(t *testing.T) {
	// A check declaring Consumes = KindEndpoint must NOT receive
	// the crawler's KindPage targets. Confirmed by feeding only a
	// crawler page and asserting the endpoint consumer never runs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	consume := &endpointConsumingCheck{name: "consume-only"}

	s := New(newNilClient(), []core.Check{consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seen) != 0 {
		t.Errorf("endpoint consumer ran %d times against crawler KindPage; want 0", len(consume.seen))
	}
}
