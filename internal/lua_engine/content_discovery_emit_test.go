package lua_engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/target"
)

// TestContentDiscoveryEmitsInteractiveSurfaces drives the real
// content_discovery.lua against an httptest server that responds to
// both an interactive surface (/admin/, Emit=true in the catalog) and
// a file-disclosure surface (/.env, Emit=false). The expectation:
//
//   - both produce findings
//   - only /admin/ emits a follow-on KindPage discovery target
//
// The check is run with the operator-supplied scan level set to
// aggressive so the catalog entries marked Aggressive=true (which
// includes /admin/) are included in the sweep.
func TestContentDiscoveryEmitsInteractiveSurfaces(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Admin Panel</h1><form action='/login'>...</form></body></html>"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DB_HOST=localhost\nDB_USER=root\nDB_PASSWORD=secret\n"))
	})
	// Catch-all returns a consistent 404 body so the baseline canary
	// probes converge on a single soft-404 fingerprint and miss-shape
	// responses get correctly classified.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 not found</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := loadCatalogCheck(t, "content_discovery.lua")

	var emittedMu sync.Mutex
	var emitted []target.Target
	ctx := core.WithDiscoverer(context.Background(), func(t target.Target) {
		emittedMu.Lock()
		emitted = append(emitted, t)
		emittedMu.Unlock()
	})
	// Aggressive level so the /admin/ entry (Aggressive=true) is in
	// the sweep set.
	ctx = core.WithLevel(ctx, core.LevelAggressive)

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var sawAdmin, sawEnv bool
	for _, f := range findings {
		if strings.Contains(f.URL, "/admin/") {
			sawAdmin = true
		}
		if strings.Contains(f.URL, "/.env") {
			sawEnv = true
		}
	}
	if !sawAdmin {
		t.Errorf("expected a finding for /admin/, got none; findings: %d", len(findings))
	}
	if !sawEnv {
		t.Errorf("expected a finding for /.env, got none; findings: %d", len(findings))
	}

	emittedMu.Lock()
	defer emittedMu.Unlock()
	var sawAdminEmit, sawEnvEmit bool
	var emittedURLs []string
	for _, e := range emitted {
		emittedURLs = append(emittedURLs, e.URL)
		if e.Kind != target.KindPage {
			t.Errorf("emitted target kind = %v, want KindPage", e.Kind)
		}
		if strings.Contains(e.URL, "/admin/") {
			sawAdminEmit = true
		}
		if strings.Contains(e.URL, "/.env") {
			sawEnvEmit = true
		}
	}
	if !sawAdminEmit {
		t.Errorf("expected ctx.discover to fire for /admin/ (Emit=true); emitted URLs: %v", emittedURLs)
	}
	if sawEnvEmit {
		t.Errorf("/.env should NOT emit a discovery (file disclosure, Emit=false); emitted URLs: %v", emittedURLs)
	}
}
