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

func findCacheControl(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cache-control-sensitive" {
			return c
		}
	}
	t.Fatal("cache-control-sensitive Lua check not found in embedded catalog")
	return nil
}

func TestLuaCacheControlSensitiveNameLevel(t *testing.T) {
	c := findCacheControl(t)
	if c.Name() != "cache-control-sensitive" {
		t.Fatalf("Name = %q", c.Name())
	}
	if c.Level() != checks.LevelPassive {
		t.Fatalf("Level = %v, want passive", c.Level())
	}
}

// TestLuaCacheControlSensitiveParity exercises the same scenarios the
// Go check's own tests cover and locks in 1:1 finding count, severity,
// title shape, and dedupe key with the Go original. A drift between
// the two implementations - even a one-character change in the
// dedupe-parts vocabulary - fails here.
func TestLuaCacheControlSensitiveParity(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "private_no_finding",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "private, no-cache")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html></html>"))
			},
		},
		{
			name: "public_only_flags",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html></html>"))
			},
		},
		{
			name: "missing_header_flags",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html></html>"))
			},
		},
		{
			name: "pragma_only_no_finding",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Pragma", "no-cache")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html></html>"))
			},
		},
		{
			name: "non_html_ignored",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("{}"))
			},
		},
	}

	luaC := findCacheControl(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			goFs, err := (checks.CacheControlSensitive{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
			if err != nil {
				t.Fatalf("go Run: %v", err)
			}
			luaFs, err := luaC.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
			if err != nil {
				t.Fatalf("lua Run: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count mismatch: go=%d lua=%d (go=%+v lua=%+v)", len(goFs), len(luaFs), goFs, luaFs)
			}
			for i := range goFs {
				if goFs[i].DedupeKey != luaFs[i].DedupeKey {
					t.Errorf("[%d] dedupe drift: go=%q lua=%q", i, goFs[i].DedupeKey, luaFs[i].DedupeKey)
				}
				if goFs[i].Severity != luaFs[i].Severity {
					t.Errorf("[%d] severity drift: go=%q lua=%q", i, goFs[i].Severity, luaFs[i].Severity)
				}
				if goFs[i].CWE != luaFs[i].CWE {
					t.Errorf("[%d] cwe drift: go=%q lua=%q", i, goFs[i].CWE, luaFs[i].CWE)
				}
			}
		})
	}
}

func TestLuaCacheControlSensitiveDetailMentionsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()
	fs, err := findCacheControl(t).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Detail, "missing") {
		t.Errorf("Detail should mention missing headers: %q", fs[0].Detail)
	}
}
