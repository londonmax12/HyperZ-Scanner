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

func findCORSReflection(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "cors-reflection" {
			return c
		}
	}
	t.Fatal("cors-reflection Lua check not found")
	return nil
}

// TestLuaCORSReflectionParity runs each server shape through both the
// Go and Lua implementations and locks in identical finding count +
// dedupe key + severity. The Go check is the parity oracle.
func TestLuaCORSReflectionParity(t *testing.T) {
	// 1) Server that echoes Origin into ACAO with credentials.
	reflectingCredSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer reflectingCredSrv.Close()

	// 2) Server that echoes Origin without credentials.
	reflectingSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer reflectingSrv.Close()

	// 3) Server that never echoes Origin (no CORS at all).
	staticSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer staticSrv.Close()

	luaC := findCORSReflection(t)
	client := newTestClient(t)
	var sc *scope.Scope

	cases := []struct {
		name string
		url  string
	}{
		{"reflects_with_credentials_high", reflectingCredSrv.URL},
		{"reflects_without_credentials_medium", reflectingSrv.URL},
		{"no_cors_no_finding", staticSrv.URL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			goFs, err := (checks.CORSReflection{}).Run(context.Background(), client, sc, page.FromURL(tc.url))
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
					t.Errorf("severity drift: go=%q lua=%q", goFs[i].Severity, luaFs[i].Severity)
				}
			}
		})
	}
}
