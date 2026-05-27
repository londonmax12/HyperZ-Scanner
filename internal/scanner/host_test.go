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

// hostEmittingCheck emits one KindHost discovery per Run. Used to
// drive the host-materialization round-trip test: an upstream check
// surfaces a scheme://host scan unit (e.g. for cert posture or vendor
// fingerprint sweeps), the worker hands it to a downstream check that
// declares Consumes = KindHost.
type hostEmittingCheck struct {
	name    string
	hostURL string
}

func (e *hostEmittingCheck) Name() string      { return e.name }
func (e *hostEmittingCheck) Level() core.Level { return core.LevelPassive }
func (e *hostEmittingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	core.Discover(ctx, target.Host(e.hostURL, ""))
	return nil, nil
}

// hostConsumingCheck declares Consumes = KindHost so it receives only
// host dispatches. It records the Target via core.TargetFrom and the
// p.URL it was handed, so the test can assert the worker delivered a
// minimal page.Page{URL: hostURL} (no fetch) just like KindEndpoint.
type hostConsumingCheck struct {
	name    string
	mu      sync.Mutex
	seen    []target.Target
	seenURL []string
}

func (e *hostConsumingCheck) Name() string                 { return e.name }
func (e *hostConsumingCheck) Level() core.Level            { return core.LevelPassive }
func (e *hostConsumingCheck) Tier() core.Tier              { return core.TierActive }
func (e *hostConsumingCheck) Consumes() []target.Kind      { return []target.Kind{target.KindHost} }
func (e *hostConsumingCheck) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]core.Finding, error) {
	e.mu.Lock()
	e.seen = append(e.seen, core.TargetFrom(ctx))
	e.seenURL = append(e.seenURL, p.URL)
	e.mu.Unlock()
	return nil, nil
}

func TestHostDiscoveryRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	emit := &hostEmittingCheck{name: "emit-host", hostURL: srv.URL}
	consume := &hostConsumingCheck{name: "consume-host"}

	s := New(newNilClient(), []core.Check{emit, consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seen) != 1 {
		t.Fatalf("host consumer Run count = %d, want 1; seen URLs: %v", len(consume.seen), consume.seenURL)
	}
	got := consume.seen[0]
	if got.Kind != target.KindHost {
		t.Errorf("dispatched target Kind = %v, want KindHost", got.Kind)
	}
	if got.URL != srv.URL {
		t.Errorf("dispatched target URL = %q, want %q", got.URL, srv.URL)
	}
	if got.Origin != "check:emit-host" {
		t.Errorf("dispatched target Origin = %q, want check:emit-host", got.Origin)
	}
	if consume.seenURL[0] != srv.URL {
		t.Errorf("consumer received page.URL = %q, want %q (KindHost materializes to bare scheme://host)", consume.seenURL[0], srv.URL)
	}
}

// TestHostMaterializationDoesNotFetch confirms the worker does NOT
// issue a GET against the host root when materializing a KindHost
// target. Mirrors TestEndpointMaterializationDoesNotFetch: the
// per-host probe set is the check's responsibility (cert posture,
// banner inspection, vendor-specific probes), and an unsolicited GET
// /  would burn a request the operator did not authorize and could
// trip a WAF before the real check fires.
func TestHostMaterializationDoesNotFetch(t *testing.T) {
	var hits int
	var hitsMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			hitsMu.Lock()
			hits++
			hitsMu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	emit := &hostEmittingCheck{name: "emit-host", hostURL: srv.URL}
	consume := &hostConsumingCheck{name: "consume-host"}

	s := New(newNilClient(), []core.Check{emit, consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	hitsMu.Lock()
	defer hitsMu.Unlock()
	// hits counts GET / against srv. The seed (srv.URL+"/") goes
	// through the crawler-origin path so no fetch on materialization,
	// and the KindHost discovery uses the no-fetch materializer. Net
	// expected GET-/ count: 0 from the worker itself, but the
	// fingerprint Detector may still issue a baseline probe - assert
	// at most one hit so a future Detector regression that fanned out
	// GETs would surface.
	if hits > 1 {
		t.Errorf("server received %d hits on /; want <= 1 (KindHost must not be fetched by the worker)", hits)
	}
	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seen) != 1 {
		t.Errorf("downstream consumer should still have dispatched; got %d runs", len(consume.seen))
	}
}

// TestHostConsumerNotDispatchedAgainstKindPage confirms a check
// declaring Consumes = KindHost does NOT receive crawler-origin
// KindPage targets. Same shape as the endpoint / param kind-filter
// tests; pins the dispatcher's consumesKind behavior for KindHost.
func TestHostConsumerNotDispatchedAgainstKindPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	consume := &hostConsumingCheck{name: "consume-only"}

	s := New(newNilClient(), []core.Check{consume})

	if _, err := runOne(context.Background(), s, srv.URL+"/"); err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	consume.mu.Lock()
	defer consume.mu.Unlock()
	if len(consume.seen) != 0 {
		t.Errorf("host consumer ran %d times against crawler KindPage; want 0", len(consume.seen))
	}
}
