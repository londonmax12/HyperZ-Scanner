package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findContentDiscovery(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "content-discovery" {
			return c
		}
	}
	t.Fatal("content-discovery Lua check not found")
	return nil
}

// discoveryMockServer builds a server with a fixed routing map plus
// a clean 404 for everything else. Canary baseline probes always fall
// through to the 404 path.
func discoveryMockServer(routes map[string]func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found\n"))
	}))
}

func discoveryFindingForPath(fs []checks.Finding, path string) *checks.Finding {
	for i := range fs {
		if strings.HasSuffix(fs[i].URL, path) {
			return &fs[i]
		}
	}
	return nil
}

// TestLuaContentDiscoveryGitMarkerParity asserts both implementations
// fire on a .git/HEAD marker-match and the per-finding shape lines
// up (severity, title, CWE, dedupe key).
func TestLuaContentDiscoveryGitMarkerParity(t *testing.T) {
	srv := discoveryMockServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		},
	})
	defer srv.Close()

	p := page.FromURL(srv.URL + "/")
	client := newTestClient(t)

	goFs, err := (&checks.ContentDiscovery{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	goF := discoveryFindingForPath(goFs, "/.git/HEAD")
	if goF == nil {
		t.Fatalf("go: expected /.git/HEAD finding, got %+v", goFs)
	}

	luaC := findContentDiscovery(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	luaF := discoveryFindingForPath(luaFs, "/.git/HEAD")
	if luaF == nil {
		t.Fatalf("lua: expected /.git/HEAD finding, got %+v", luaFs)
	}

	if goF.Severity != luaF.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goF.Severity, luaF.Severity)
	}
	if goF.CWE != luaF.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goF.CWE, luaF.CWE)
	}
	if goF.OWASP != luaF.OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goF.OWASP, luaF.OWASP)
	}
	if !strings.Contains(goF.Title, "marker-match") || !strings.Contains(luaF.Title, "marker-match") {
		t.Errorf("expected marker-match verdict in both titles\n go=%q\nlua=%q", goF.Title, luaF.Title)
	}
	if goF.DedupeKey != luaF.DedupeKey {
		t.Errorf("dedupe drift:\n go=%q\nlua=%q", goF.DedupeKey, luaF.DedupeKey)
	}
}

// TestLuaContentDiscoveryMarkerRequiredSuppressesSoft200 asserts both
// implementations suppress a /.git/HEAD 200 whose body does not match
// the marker (the body is overwhelmingly a soft-404 wrapper, not the
// genuine artifact).
func TestLuaContentDiscoveryMarkerRequiredSuppressesSoft200(t *testing.T) {
	srv := discoveryMockServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		},
	})
	defer srv.Close()

	p := page.FromURL(srv.URL + "/")
	client := newTestClient(t)

	goFs, err := (&checks.ContentDiscovery{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if discoveryFindingForPath(goFs, "/.git/HEAD") != nil {
		t.Errorf("go: marker-absent /.git/HEAD must be suppressed: %+v", goFs)
	}

	luaC := findContentDiscovery(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if discoveryFindingForPath(luaFs, "/.git/HEAD") != nil {
		t.Errorf("lua: marker-absent /.git/HEAD must be suppressed: %+v", luaFs)
	}
}

// TestLuaContentDiscoveryAuthGatedParity asserts both implementations
// surface a 401-shaped finding on /actuator/env and the per-finding
// shape matches.
func TestLuaContentDiscoveryAuthGatedParity(t *testing.T) {
	srv := discoveryMockServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/actuator/env": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		},
	})
	defer srv.Close()

	p := page.FromURL(srv.URL + "/")
	client := newTestClient(t)

	goFs, err := (&checks.ContentDiscovery{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	goF := discoveryFindingForPath(goFs, "/actuator/env")
	if goF == nil {
		t.Fatalf("go: expected /actuator/env finding, got %+v", goFs)
	}

	luaC := findContentDiscovery(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	luaF := discoveryFindingForPath(luaFs, "/actuator/env")
	if luaF == nil {
		t.Fatalf("lua: expected /actuator/env finding, got %+v", luaFs)
	}

	if goF.Severity != luaF.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goF.Severity, luaF.Severity)
	}
	if !strings.Contains(goF.Title, "auth-gated") || !strings.Contains(luaF.Title, "auth-gated") {
		t.Errorf("expected auth-gated verdict in both titles\n go=%q\nlua=%q", goF.Title, luaF.Title)
	}
	if goF.DedupeKey != luaF.DedupeKey {
		t.Errorf("dedupe drift:\n go=%q\nlua=%q", goF.DedupeKey, luaF.DedupeKey)
	}
}

// TestLuaContentDiscoveryFollowUpsTriggerAfterGitHit asserts both
// implementations expand on a /.git/HEAD hit and probe the .git/*
// follow-up family.
func TestLuaContentDiscoveryFollowUpsTriggerAfterGitHit(t *testing.T) {
	srv := discoveryMockServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		},
		"/.git/logs/HEAD": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000 abc\n"))
		},
		"/.git/index": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("DIRC\x00\x00\x00\x02"))
		},
	})
	defer srv.Close()

	p := page.FromURL(srv.URL + "/")
	client := newTestClient(t)

	goFs, err := (&checks.ContentDiscovery{}).Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if discoveryFindingForPath(goFs, "/.git/logs/HEAD") == nil {
		t.Errorf("go: expected /.git/logs/HEAD follow-up finding: %+v", goFs)
	}

	luaC := findContentDiscovery(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if discoveryFindingForPath(luaFs, "/.git/logs/HEAD") == nil {
		t.Errorf("lua: expected /.git/logs/HEAD follow-up finding: %+v", luaFs)
	}
	if discoveryFindingForPath(luaFs, "/.git/index") == nil {
		t.Errorf("lua: expected /.git/index follow-up finding: %+v", luaFs)
	}
}
