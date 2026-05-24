package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestPathTraversalName(t *testing.T) {
	if got := (PathTraversal{}).Name(); got != "path-traversal" {
		t.Fatalf("Name = %q, want path-traversal", got)
	}
}

func TestPathTraversalLevel(t *testing.T) {
	if got := (PathTraversal{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnTraversalHandler simulates a backend that takes the `file` query
// param and reads it from disk without normalization. Any value
// containing the literal "etc/passwd" is "served" by returning a
// passwd-shaped body. Benign values yield a 200 OK with no markers.
func vulnTraversalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if strings.Contains(f, "etc/passwd") || strings.Contains(f, "etc%2fpasswd") || strings.Contains(f, "etc%252fpasswd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		_, _ = w.Write([]byte("file contents for: " + f))
	})
}

func TestPathTraversalDetectsEtcPasswdDisclosure(t *testing.T) {
	srv := httptest.NewServer(vulnTraversalHandler())
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/download?file=report.txt"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-22" {
		t.Errorf("CWE = %q, want CWE-22", f.CWE)
	}
	if !strings.Contains(f.Title, "file") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "root:x:0:0:") {
		t.Errorf("Detail should mention the disclosed passwd marker: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
}

func TestPathTraversalDetectsWindowsHostsDisclosure(t *testing.T) {
	// Cross-platform coverage: a backend on Windows discloses the hosts
	// file. The check must catch this without OS-specific branching.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// Match Windows-shaped traversal: the catalog payload contains
		// `windows\system32`.
		if strings.Contains(f, "windows") && strings.Contains(f, "hosts") {
			_, _ = w.Write([]byte("# Copyright (c) 1993-2009 Microsoft Corp.\n127.0.0.1       localhost\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/download?file=report.txt"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "Microsoft") && !strings.Contains(findings[0].Detail, "127.0.0.1") {
		t.Errorf("Detail should mention the disclosed Windows marker: %q", findings[0].Detail)
	}
}

func TestPathTraversalEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnTraversalHandler())
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/download?file=report.txt"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	ev := findings[0].Evidence
	if ev == nil || ev.Exchange == nil {
		t.Fatalf("Evidence/Exchange missing: %+v", ev)
	}
	if !strings.Contains(ev.Exchange.ResponseBody, "root:x:0:0:") {
		t.Errorf("Exchange should carry the disclosed passwd content: %q", ev.Exchange.ResponseBody)
	}
	if ev.Snippet == "" {
		t.Errorf("Evidence snippet should be populated")
	}
}

func TestPathTraversalNoFindingOnRobustHandler(t *testing.T) {
	// Backend normalizes paths and refuses traversal. Body never
	// contains any traversal markers, no finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("safe content"))
	}))
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/download?file=report.txt"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe handler, got %d: %+v", len(findings), findings)
	}
}

func TestPathTraversalBaselineSubtractionSuppressesFalsePositive(t *testing.T) {
	// Docs page that always describes /etc/passwd line shape - including
	// the literal `root:x:0:0:` marker. The baseline-subtraction logic
	// must drop the pattern since it isn't introduced by our probe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<p>Example: root:x:0:0:root:/root:/bin/bash is the canonical superuser line.</p>"))
	}))
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/docs?file=test.txt"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when marker is in baseline, got %d: %+v", len(findings), findings)
	}
}

func TestPathTraversalSkipsNonPathishSinkAtDefault(t *testing.T) {
	// `email` is not in pathParamKeywords and its value carries no
	// path-shaped character. At LevelDefault the sink must be skipped
	// entirely - no probe fires. The handler counter pins this.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?email=alice"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on non-path-ish sink, got %d: %+v", len(findings), findings)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; non-path-ish sink must not be probed at default level", got)
	}
}

func TestPathTraversalProbesSinkWithPathishValue(t *testing.T) {
	// `q` isn't in pathParamKeywords, but its value already carries a
	// path-shaped character (`.`). The check should probe it on the
	// strength of that signal and catch the disclosure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if strings.Contains(v, "etc/passwd") || strings.Contains(v, "etc%2fpasswd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/?q=foo.txt"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from path-shaped value, got %d: %+v", len(findings), findings)
	}
}

func TestPathTraversalAggressiveProbesEverySink(t *testing.T) {
	// At LevelAggressive the name/value heuristic is bypassed. `email`
	// (which would skip at default) gets probed and the bug fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("email")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if strings.Contains(v, "etc/passwd") || strings.Contains(v, "etc%2fpasswd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := PathTraversal{}.Run(ctx, newTestClient(t),
		nil, page.FromURL(srv.URL+"/?email=alice"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding at LevelAggressive on non-path-ish sink, got %d: %+v", len(findings), findings)
	}
}

func TestPathTraversalRespectsScope(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t), sc,
		page.FromURL(srv.URL+"/?file=test.txt"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings out of scope, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; out-of-scope check must not probe", got)
	}
}

func TestPathTraversalNoProbeWhenNoSinks(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL(srv.URL+"/static"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sinks, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; no-sinks page must not be probed", got)
	}
}

func TestPathTraversalDedupeKeyStableAndPerParam(t *testing.T) {
	srv := httptest.NewServer(vulnTraversalHandler())
	defer srv.Close()

	run := func(rawurl string) string {
		fs, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
			nil, page.FromURL(rawurl))
		if err != nil {
			t.Fatalf("Run %q: %v", rawurl, err)
		}
		if len(fs) != 1 {
			t.Fatalf("Run %q: got %d findings, want 1", rawurl, len(fs))
		}
		return fs[0].DedupeKey
	}
	a := run(srv.URL + "/download?file=report.txt")
	b := run(srv.URL + "/download?file=other.txt") // same param, different value, same key
	if a == "" {
		t.Fatal("DedupeKey empty")
	}
	if a != b {
		t.Errorf("same-param keys drifted: %q vs %q", a, b)
	}
}

func TestPathTraversalIgnoresUnparseableTarget(t *testing.T) {
	findings, err := PathTraversal{}.Run(context.Background(), newTestClient(t),
		nil, page.FromURL("::not-a-url::"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on garbage URL, got %d", len(findings))
	}
}

func TestPathSinkCandidate(t *testing.T) {
	cases := []struct {
		name  string
		sink  Sink
		want  bool
		label string
	}{
		{"path-keyword: file", Sink{Name: "file"}, true, "file name"},
		{"path-keyword: filename", Sink{Name: "filename"}, true, "filename"},
		{"path-keyword: template", Sink{Name: "tplName"}, true, "substring tpl"},
		{"path-keyword: include", Sink{Name: "include_target"}, true, "substring include"},
		{"path-shaped value: dot", Sink{Name: "q", Value: "foo.txt"}, true, "dotted value"},
		{"path-shaped value: slash", Sink{Name: "q", Value: "a/b"}, true, "slashed value"},
		{"path-shaped value: backslash", Sink{Name: "q", Value: `C:\x`}, true, "windows value"},
		{"plain alphabetic", Sink{Name: "email", Value: "alice"}, false, "no match"},
		{"empty value, plain name", Sink{Name: "id", Value: ""}, false, "no signal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathSinkCandidate(tc.sink); got != tc.want {
				t.Errorf("pathSinkCandidate(%+v) = %v, want %v (%s)", tc.sink, got, tc.want, tc.label)
			}
		})
	}
}

func TestMatchTraversalMarkers(t *testing.T) {
	body := []byte("Stack trace:\nroot:x:0:0:root:/root:/bin/bash\n  at handler.go:42")
	hits := matchTraversalMarkers(body)
	if len(hits) == 0 {
		t.Fatal("expected at least one hit on the canonical passwd marker")
	}
	found := false
	for _, h := range hits {
		if strings.Contains(h, "root:x:0:0:") {
			found = true
		}
	}
	if !found {
		t.Errorf("hits = %+v, want one mentioning root:x:0:0:", hits)
	}
}

func TestMatchTraversalMarkersEmpty(t *testing.T) {
	if got := matchTraversalMarkers(nil); got != nil {
		t.Errorf("empty body should yield nil hits, got %+v", got)
	}
	if got := matchTraversalMarkers([]byte("totally benign content")); got != nil {
		t.Errorf("clean body should yield nil hits, got %+v", got)
	}
}
