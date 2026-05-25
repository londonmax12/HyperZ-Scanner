package checks_lua

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findXXE(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "xxe" {
			return c
		}
	}
	t.Fatal("xxe Lua check not found")
	return nil
}

// xxeMockFileHandler simulates a backend that resolves SYSTEM
// entities and inlines /etc/passwd into the response.
func xxeMockFileHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `SYSTEM "file:///etc/passwd"`) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("parsed: <foo>root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh</foo>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// xxeMockErrorHandler simulates a backend that surfaces libxml-shaped
// parser errors on undefined entities without resolving externals.
func xxeMockErrorHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "hyperz_undefined_xxe_canary") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("XML parsing error: Undefined entity: hyperz_undefined_xxe_canary at line 1 column 42"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// TestLuaXXEFileDisclosureParity asserts both implementations produce
// a Critical file-disclosure finding with byte-aligned severity / CWE
// / OWASP / DedupeKey when the backend dereferences SYSTEM entities.
func TestLuaXXEFileDisclosureParity(t *testing.T) {
	srv := httptest.NewServer(xxeMockFileHandler())
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	client := newTestClient(t)

	goFs, err := checks.XXE{}.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) == 0 {
		t.Fatalf("go: expected at least one file-disclosure finding, got 0")
	}
	luaC := findXXE(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) == 0 {
		t.Fatalf("lua: expected at least one file-disclosure finding, got 0")
	}

	goF := goFs[0]
	luaF := luaFs[0]
	if goF.Severity != luaF.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goF.Severity, luaF.Severity)
	}
	if goF.CWE != luaF.CWE {
		t.Errorf("CWE drift: go=%q lua=%q", goF.CWE, luaF.CWE)
	}
	if goF.OWASP != luaF.OWASP {
		t.Errorf("OWASP drift: go=%q lua=%q", goF.OWASP, luaF.OWASP)
	}
	if !strings.Contains(goF.Title, "file disclosure") || !strings.Contains(luaF.Title, "file disclosure") {
		t.Errorf("title should mention file disclosure\n go=%q\nlua=%q", goF.Title, luaF.Title)
	}
	if goF.DedupeKey != luaF.DedupeKey {
		t.Errorf("dedupe drift:\n go=%q\nlua=%q", goF.DedupeKey, luaF.DedupeKey)
	}
}

// TestLuaXXEErrorBasedParity asserts both implementations produce a
// High-severity error-based finding when the backend leaks parser
// error signatures without resolving externals.
func TestLuaXXEErrorBasedParity(t *testing.T) {
	srv := httptest.NewServer(xxeMockErrorHandler())
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	client := newTestClient(t)

	goFs, err := checks.XXE{}.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) == 0 {
		t.Fatalf("go: expected at least one error-based finding, got 0")
	}
	luaC := findXXE(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) == 0 {
		t.Fatalf("lua: expected at least one error-based finding, got 0")
	}

	goF := goFs[0]
	luaF := luaFs[0]
	if goF.Severity != luaF.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goF.Severity, luaF.Severity)
	}
	if !strings.Contains(goF.Title, "error-based") || !strings.Contains(luaF.Title, "error-based") {
		t.Errorf("title should mention error-based\n go=%q\nlua=%q", goF.Title, luaF.Title)
	}
	if goF.DedupeKey != luaF.DedupeKey {
		t.Errorf("dedupe drift:\n go=%q\nlua=%q", goF.DedupeKey, luaF.DedupeKey)
	}
}

// TestLuaXXEBaselineSubtractionSuppresses asserts both implementations
// suppress findings when the page always shows an XXE-shaped error
// (the baseline subtraction must catch the always-present signal).
func TestLuaXXEBaselineSubtractionSuppresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Documentation: Undefined entity errors can occur when..."))
	}))
	defer srv.Close()

	p := page.Page{
		URL: srv.URL + "/",
		Forms: []page.Form{
			{Method: http.MethodPost, Action: srv.URL + "/api"},
		},
	}
	client := newTestClient(t)

	goFs, err := checks.XXE{}.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d: %+v", len(goFs), goFs)
	}
	luaC := findXXE(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d: %+v", len(luaFs), luaFs)
	}
}

// TestLuaXXENoCandidatesNoProbes asserts both implementations skip a
// page with no XML hint, no forms, no SpecOps.
func TestLuaXXENoCandidatesNoProbes(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.FromURL(srv.URL + "/static.html")
	client := newTestClient(t)

	goFs, err := checks.XXE{}.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	if len(goFs) != 0 {
		t.Fatalf("go: expected 0 findings, got %d", len(goFs))
	}
	hits = 0

	luaC := findXXE(t)
	luaFs, err := luaC.Run(context.Background(), client, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(luaFs) != 0 {
		t.Fatalf("lua: expected 0 findings, got %d", len(luaFs))
	}
	if hits != 0 {
		t.Fatalf("server hit %d times; no-candidate page must not be probed", hits)
	}
}
