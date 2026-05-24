package checks

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestContentDiscoveryName(t *testing.T) {
	if got := (&ContentDiscovery{}).Name(); got != "content-discovery" {
		t.Fatalf("Name = %q, want content-discovery", got)
	}
}

func TestContentDiscoveryLevel(t *testing.T) {
	if got := (&ContentDiscovery{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// discoveryServer builds a server with a fixed routing map plus a clean
// 404 for everything else. canary-shaped baseline probes always fall
// through to the 404 path.
func discoveryServer(routes map[string]func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found\n"))
	}))
}

func TestContentDiscoveryFiresOnGitMarker(t *testing.T) {
	srv := discoveryServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		},
	})
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := findingForPath(findings, "/.git/HEAD")
	if got == nil {
		t.Fatalf("expected /.git/HEAD finding, got %+v", findings)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", got.Severity)
	}
	if !strings.Contains(got.Title, "marker-match") {
		t.Errorf("Title should record marker-match verdict: %q", got.Title)
	}
	if got.CWE != "CWE-538" {
		t.Errorf("CWE = %q, want CWE-538", got.CWE)
	}
}

func TestContentDiscoveryMarkerRequiredSuppressesSoft200(t *testing.T) {
	// /.git/HEAD returns 200 with a body that doesn't match the marker.
	// classifyDiscovery must suppress: a 200 without the expected marker
	// is overwhelmingly a soft-404 wrapper, not a real .git exposure.
	srv := discoveryServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>welcome</body></html>"))
		},
	})
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := findingForPath(findings, "/.git/HEAD"); got != nil {
		t.Errorf("expected no /.git/HEAD finding (marker absent), got %+v", got)
	}
}

func TestContentDiscoverySuppressesCatchAll(t *testing.T) {
	// Every path - including the random canaries - returns the same
	// 200 OK SPA shell. The baseline must learn this and silently
	// drop probes whose markerless body matches.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html><body>SPA shell</body></html>"))
	}))
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		// The markerless entries (admin/, sitemap.xml, etc.) all live on
		// the aggressive tier so don't probe here, but if anything
		// shape-matches the SPA shell we mustn't fire.
		t.Errorf("expected zero findings on a pure SPA catch-all, got: %+v", f)
	}
}

func TestContentDiscoveryFiresOnAuthGated(t *testing.T) {
	// Server returns 401 for /actuator/env: the resource exists and is
	// behind an auth gate. ContentDiscovery should report it.
	srv := discoveryServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/actuator/env": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
		},
	})
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := findingForPath(findings, "/actuator/env")
	if got == nil {
		t.Fatalf("expected /actuator/env finding, got %+v", findings)
	}
	if !strings.Contains(got.Title, "auth-gated") {
		t.Errorf("Title should record auth-gated verdict: %q", got.Title)
	}
	if got.Evidence == nil || got.Evidence.Status != http.StatusUnauthorized {
		t.Errorf("Evidence should record the 401 status: %+v", got.Evidence)
	}
}

func TestContentDiscoveryPerHostGate(t *testing.T) {
	// Two pages on the same host should only trigger the sweep once.
	// Count incoming requests; the second Run must add zero.
	var count int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	check := &ContentDiscovery{}
	if _, err := check.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/page-one")); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	firstCount := atomic.LoadInt64(&count)
	if firstCount == 0 {
		t.Fatalf("expected probes on first Run, got 0")
	}
	if _, err := check.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/page-two")); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := atomic.LoadInt64(&count); got != firstCount {
		t.Errorf("second Run on same host must not re-probe: first=%d, total=%d", firstCount, got)
	}
}

func TestContentDiscoveryAggressiveTierGating(t *testing.T) {
	// /admin/ is an Aggressive: true entry. It must not probe at
	// LevelDefault and must probe at LevelAggressive.
	var adminHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/" {
			atomic.AddInt64(&adminHits, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>admin login</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Default level: /admin/ should not be probed.
	defaultCtx := WithLevel(context.Background(), LevelDefault)
	if _, err := (&ContentDiscovery{}).Run(defaultCtx, newTestClient(t), nil, page.FromURL(srv.URL+"/")); err != nil {
		t.Fatalf("default Run: %v", err)
	}
	if got := atomic.LoadInt64(&adminHits); got != 0 {
		t.Errorf("LevelDefault must skip /admin/ (Aggressive: true), got %d hits", got)
	}

	// Aggressive level: /admin/ should be probed at least once.
	aggCtx := WithLevel(context.Background(), LevelAggressive)
	if _, err := (&ContentDiscovery{}).Run(aggCtx, newTestClient(t), nil, page.FromURL(srv.URL+"/")); err != nil {
		t.Fatalf("aggressive Run: %v", err)
	}
	if got := atomic.LoadInt64(&adminHits); got == 0 {
		t.Errorf("LevelAggressive must probe /admin/, got 0 hits")
	}
}

func TestContentDiscoveryEnvFiresWithMarker(t *testing.T) {
	srv := discoveryServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.env": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("DATABASE_URL=postgres://user:pass@db/app\nSECRET_KEY=abc123\n"))
		},
	})
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := findingForPath(findings, "/.env")
	if got == nil {
		t.Fatalf("expected /.env finding, got %+v", findings)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", got.Severity)
	}
}

func TestContentDiscoveryRedirectMatchingBaselineSuppressed(t *testing.T) {
	// Catch-all redirect to /login - both the random baseline and
	// our probes return 302 to the same Location. classifyDiscovery
	// must drop the probes as soft-404-equivalent.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		t.Errorf("expected zero findings on catch-all redirect, got: %+v", f)
	}
}

func TestContentDiscoveryDedupesPerHost(t *testing.T) {
	// One host, /.git/HEAD reachable. Even if multiple entries could
	// theoretically dedupe-clash, MakeKey scopes on host+path so each
	// path emits exactly once.
	srv := discoveryServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		},
		"/.git/config": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("[core]\nrepositoryformatversion = 0\n"))
		},
	})
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Each path produces its own finding; both should be present.
	if findingForPath(findings, "/.git/HEAD") == nil {
		t.Errorf("missing /.git/HEAD finding")
	}
	if findingForPath(findings, "/.git/config") == nil {
		t.Errorf("missing /.git/config finding")
	}
	seen := map[string]int{}
	for _, f := range findings {
		seen[f.DedupeKey]++
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("dedupe key %s appears %d times, want 1", k, n)
		}
	}
}

func TestClassifyDiscoveryRespectsBaselineStatus(t *testing.T) {
	// Pure unit test for the classifier: baseline returned 200 catch-all,
	// candidate returns 200 with the same body hash - must be suppressed.
	body := []byte("<html>SPA shell</html>")
	b := discoveryBaseline{
		statuses:    map[int]struct{}{200: {}},
		bodyHashes:  map[string]struct{}{bodyHashPrefix(body): {}},
		bodyLens:    []int{len(body)},
		contentType: "text/html",
	}
	entry := discoveryEntry{Path: "/admin/", Severity: SeverityLow}
	verdict, _, _ := classifyDiscovery(entry, b, 200, body, "text/html; charset=utf-8", "")
	if verdict != "" {
		t.Errorf("expected suppression on baseline match, got verdict %q", verdict)
	}
}

func TestClassifyDiscoveryShapeDistinct(t *testing.T) {
	// Baseline is a 404; candidate returns 200 with non-matching body
	// and no marker. classifyDiscovery emits "200-distinct".
	b := discoveryBaseline{
		statuses:   map[int]struct{}{404: {}},
		bodyHashes: map[string]struct{}{bodyHashPrefix([]byte("not found\n")): {}},
		bodyLens:   []int{len("not found\n")},
	}
	entry := discoveryEntry{Path: "/admin/", Severity: SeverityLow}
	body := []byte(strings.Repeat("a", 2048))
	verdict, _, sev := classifyDiscovery(entry, b, 200, body, "text/html", "")
	if verdict != "200-distinct" {
		t.Errorf("expected 200-distinct verdict, got %q", verdict)
	}
	if sev != SeverityLow {
		t.Errorf("expected severity carried through from entry, got %q", sev)
	}
}

func TestLengthCloseTo(t *testing.T) {
	cases := []struct {
		a, b int
		want bool
	}{
		{100, 100, true},
		{100, 150, true},   // within absolute slack
		{1000, 1010, true}, // within absolute slack
		{1000, 2000, false},
		{10000, 10400, true}, // 4% < 5% relative slack
		{10000, 11000, false},
	}
	for _, c := range cases {
		if got := lengthCloseTo(c.a, c.b); got != c.want {
			t.Errorf("lengthCloseTo(%d,%d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestContentTypeFamily(t *testing.T) {
	cases := map[string]string{
		"text/html; charset=utf-8": "text/html",
		"application/JSON":         "application/json",
		"":                         "",
		"text/plain":               "text/plain",
	}
	for in, want := range cases {
		if got := contentTypeFamily(in); got != want {
			t.Errorf("contentTypeFamily(%q) = %q, want %q", in, got, want)
		}
	}
}

func findingForPath(fs []Finding, path string) *Finding {
	for i := range fs {
		if strings.HasSuffix(fs[i].URL, path) {
			return &fs[i]
		}
	}
	return nil
}

func TestContentDiscoveryFollowUpsTriggerAfterGitHit(t *testing.T) {
	// /.git/HEAD hits, which must trigger the second-wave probes for
	// /.git/logs/HEAD, /.git/index, etc. Both probe URLs should be
	// requested; both findings should appear.
	srv := discoveryServer(map[string]func(w http.ResponseWriter, r *http.Request){
		"/.git/HEAD": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		},
		"/.git/logs/HEAD": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000 abc commit\n"))
		},
		"/.git/index": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("DIRC\x00\x00\x00\x02"))
		},
	})
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if findingForPath(findings, "/.git/HEAD") == nil {
		t.Fatalf("expected /.git/HEAD trigger finding, got %+v", findings)
	}
	if findingForPath(findings, "/.git/logs/HEAD") == nil {
		t.Errorf("expected follow-up /.git/logs/HEAD finding to be present")
	}
	if findingForPath(findings, "/.git/index") == nil {
		t.Errorf("expected follow-up /.git/index finding to be present")
	}
}

func TestContentDiscoveryFollowUpsSkipWithoutTrigger(t *testing.T) {
	// No trigger hits on the main sweep, so the follow-up wave must
	// not dispatch any of the /.git/logs/HEAD-style probes. Count
	// every request the server sees and confirm /.git/logs/HEAD was
	// never asked for.
	var hits int64
	var loggedFollowUp int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.URL.Path == "/.git/logs/HEAD" {
			atomic.AddInt64(&loggedFollowUp, 1)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt64(&loggedFollowUp) != 0 {
		t.Errorf("/.git/logs/HEAD probed without a trigger hit: %d times", loggedFollowUp)
	}
}

func TestContentDiscoveryHostDerivedBackup(t *testing.T) {
	// Serve a backup at /<host>.zip and confirm the synthetic
	// hostBackupEntries probes catch it. The httptest server gives us
	// a hostname like 127.0.0.1, so the entry list will include
	// "/127.0.0.1.zip".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".zip") {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(bytes.Repeat([]byte{0x50, 0x4b, 0x03, 0x04}, 128))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The server returns ZIP content for every .zip path, so the curated
	// catalog's generic /backup.zip will also produce a finding. Probe
	// dispatch is concurrent and findings arrive in completion order, so
	// we have to pick the host-named entry by name rather than by position.
	host, _, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].URL, "/"+host+".zip") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected host-derived .zip finding for host %q, got %+v", host, findings)
	}
	if hit.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", hit.Severity)
	}
	if !strings.Contains(hit.Title, "host-named backup") {
		t.Errorf("Title should record host-named verdict: %q", hit.Title)
	}
}

func TestContentDiscoveryContentTypeFamilySuppressesHTMLOnBackup(t *testing.T) {
	// Server returns 200 + HTML for everything *except* the canaries
	// (so the baseline records a 404 and the catch-all-shape check
	// doesn't suppress on its own). The synthetic backup entries
	// carry ExpectedContentTypes that exclude text/html; the probe
	// must therefore be suppressed despite being 200-distinct.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".bad") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><html><body>" + strings.Repeat("x", 4096) + "</body></html>"))
	}))
	defer srv.Close()

	findings, err := (&ContentDiscovery{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL+"/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.HasSuffix(f.URL, ".zip") || strings.HasSuffix(f.URL, ".sql") || strings.HasSuffix(f.URL, ".tar.gz") || strings.HasSuffix(f.URL, ".bak") {
			t.Errorf("text/html on a backup path must be suppressed by content-type filter: %+v", f)
		}
	}
}

func TestContentTypeFamilyAllowed(t *testing.T) {
	cases := []struct {
		name    string
		ct      string
		allowed []string
		want    bool
	}{
		{"empty allow list permits anything", "text/html", nil, true},
		{"empty CT header is permissive", "", []string{"application/zip"}, true},
		{"exact match", "application/zip", []string{"application/zip"}, true},
		{"family strips charset", "text/plain; charset=utf-8", []string{"text/plain"}, true},
		{"case-insensitive allowed", "APPLICATION/ZIP", []string{"application/zip"}, true},
		{"wrong family rejected", "text/html", []string{"application/zip", "application/octet-stream"}, false},
		{"matches second entry", "application/octet-stream", []string{"application/zip", "application/octet-stream"}, true},
	}
	for _, c := range cases {
		if got := contentTypeFamilyAllowed(c.ct, c.allowed); got != c.want {
			t.Errorf("%s: contentTypeFamilyAllowed(%q, %v) = %v, want %v", c.name, c.ct, c.allowed, got, c.want)
		}
	}
}

func TestHostBackupEntries(t *testing.T) {
	// "example.com" should produce entries for both the full host and
	// the bare label "example", each combined with every extension.
	entries := hostBackupEntries("example.com")
	if len(entries) == 0 {
		t.Fatalf("expected entries for example.com")
	}
	wantPaths := []string{
		"/example.com.zip", "/example.com.tar.gz", "/example.com.sql", "/example.com.bak",
		"/example.zip", "/example.tar.gz", "/example.sql", "/example.bak",
	}
	got := map[string]struct{}{}
	for _, e := range entries {
		got[e.Path] = struct{}{}
	}
	for _, p := range wantPaths {
		if _, ok := got[p]; !ok {
			t.Errorf("missing expected entry path %q", p)
		}
	}

	// www. prefix should be stripped before label extraction so
	// www.example.com and example.com produce the same name set.
	stripped := hostBackupEntries("www.example.com")
	wantStripped := map[string]struct{}{}
	for _, e := range stripped {
		wantStripped[e.Path] = struct{}{}
	}
	for _, p := range wantPaths {
		if _, ok := wantStripped[p]; !ok {
			t.Errorf("www.example.com: missing expected entry path %q", p)
		}
	}

	// Single-label host (no dot) should still produce entries under
	// that single name, never an empty-name path.
	single := hostBackupEntries("localhost")
	for _, e := range single {
		if e.Path == "/.zip" || e.Path == "/.sql" || strings.HasPrefix(e.Path, "/.") {
			t.Errorf("localhost entry should not collapse to a dotfile path: %q", e.Path)
		}
	}
}

func TestFollowUpsForExtractsHostPath(t *testing.T) {
	// followUpsFor pulls the path out of full URLs, then matches
	// against group triggers. Confirm git triggers expand and the
	// "already probed" dedupe filters out paths in probed.
	findings := []Finding{
		{URL: "http://h.example/.git/HEAD"},
	}
	probed := map[string]struct{}{
		"/.git/index": {}, // pretend this already ran
	}
	out := followUpsFor(findings, probed)
	if len(out) == 0 {
		t.Fatalf("expected follow-ups, got none")
	}
	for _, e := range out {
		if e.Path == "/.git/index" {
			t.Errorf("/.git/index should be filtered as already probed: got %+v", e)
		}
	}
	var sawLog bool
	for _, e := range out {
		if e.Path == "/.git/logs/HEAD" {
			sawLog = true
		}
	}
	if !sawLog {
		t.Errorf("expected /.git/logs/HEAD in follow-ups, got %+v", out)
	}
}
