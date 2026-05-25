package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func findHostHeaderInjection(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "host-header-injection" {
			return c
		}
	}
	t.Fatal("host-header-injection Lua check not found")
	return nil
}

// TestLuaHostHeaderInjectionParity feeds a couple of servers (one that
// echoes the Host header into the response body, one that doesn't)
// through both implementations and locks in identical finding count
// + dedupe key. The Go check sends Host: evil.example and looks for
// the canary in the body; the Lua port does the same via the new
// `host` field on client:new_request.
func TestLuaHostHeaderInjectionParity(t *testing.T) {
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Echo Host into the body so the canary lands somewhere
		// searchable. The check looks for "evil.example" anywhere
		// case-insensitively.
		w.Write([]byte("<html><body>Welcome to " + r.Host + "</body></html>"))
	}))
	defer echoSrv.Close()

	staticSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>static</body></html>"))
	}))
	defer staticSrv.Close()

	luaC := findHostHeaderInjection(t)
	client := newTestClient(t)
	// nil Scope is "fully permissive" per scope package docs.
	var sc *scope.Scope

	cases := []struct {
		name string
		url  string
	}{
		{"reflects_host_header", echoSrv.URL},
		{"static_no_reflection", staticSrv.URL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goFs, err := (checks.HostHeaderInjection{}).Run(context.Background(), client, sc, page.FromURL(tc.url))
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaFs, err := luaC.Run(context.Background(), client, sc, page.FromURL(tc.url))
			if err != nil {
				t.Fatalf("lua: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
			}
			for i := range goFs {
				if goFs[i].DedupeKey != luaFs[i].DedupeKey {
					t.Errorf("dedupe drift: go=%q lua=%q", goFs[i].DedupeKey, luaFs[i].DedupeKey)
				}
				if goFs[i].Severity != luaFs[i].Severity {
					t.Errorf("sev drift: go=%q lua=%q", goFs[i].Severity, luaFs[i].Severity)
				}
			}
		})
	}
}
