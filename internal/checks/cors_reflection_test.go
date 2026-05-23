package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

func TestCORSReflectionName(t *testing.T) {
	if got := (CORSReflection{}).Name(); got != "cors-reflection" {
		t.Fatalf("Name = %q, want cors-reflection", got)
	}
}

func TestCORSReflectionLevel(t *testing.T) {
	if got := (CORSReflection{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// reflector echoes the request Origin verbatim into ACAO. With acac it
// also sets Access-Control-Allow-Credentials: true. The simplest possible
// reflection bug; the verbatim probe must catch it.
func reflectorHandler(acac bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			if acac {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

func TestCORSReflectionVerbatimWithCredentialsIsHigh(t *testing.T) {
	srv := httptest.NewServer(reflectorHandler(true))
	defer srv.Close()

	findings, err := CORSReflection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-942" {
		t.Errorf("CWE = %q, want CWE-942", f.CWE)
	}
	if !strings.Contains(f.Title, "verbatim") {
		t.Errorf("title should mention verbatim technique: %q", f.Title)
	}
	if !strings.Contains(f.Detail, corsReflectionCanary) {
		t.Errorf("detail should include canary origin: %q", f.Detail)
	}
}

func TestCORSReflectionVerbatimWithoutCredentialsIsMedium(t *testing.T) {
	// Reflection without credentials still leaks cross-origin reads of
	// the response body, just not authenticated state -> medium.
	srv := httptest.NewServer(reflectorHandler(false))
	defer srv.Close()

	findings, err := CORSReflection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

func TestCORSReflectionNoReflectionNoFindings(t *testing.T) {
	// Server with a real allowlist: only echoes back a hardcoded origin,
	// ignoring whatever the client sent. The canary won't match, so no
	// finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CORSReflection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("static allowlist must not fire reflection check: %+v", findings)
	}
}

func TestCORSReflectionDefaultLevelSendsOneProbe(t *testing.T) {
	// At LevelDefault only the verbatim probe should fire. Counting
	// Origin-bearing requests on the server side proves we're not
	// sending the aggressive expansion behind the user's back.
	var (
		mu      sync.Mutex
		origins []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			mu.Lock()
			origins = append(origins, o)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := (CORSReflection{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(origins) != 1 {
		t.Fatalf("expected 1 probe at LevelDefault, got %d: %v", len(origins), origins)
	}
	if origins[0] != corsReflectionCanary {
		t.Errorf("default probe origin = %q, want %q", origins[0], corsReflectionCanary)
	}
}

func TestCORSReflectionAggressiveLevelSendsAllProbes(t *testing.T) {
	var (
		mu      sync.Mutex
		origins []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			mu.Lock()
			origins = append(origins, o)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	if _, err := (CORSReflection{}).Run(ctx, newTestClient(t), nil, page.FromURL(srv.URL)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(origins) != 3 {
		t.Fatalf("expected 3 probes at LevelAggressive, got %d: %v", len(origins), origins)
	}
	want := map[string]bool{corsReflectionCanary: false, "null": false}
	for _, o := range origins {
		if _, ok := want[o]; ok {
			want[o] = true
		}
	}
	for o, seen := range want {
		if !seen {
			t.Errorf("missing probe with Origin %q; got %v", o, origins)
		}
	}
	// One of the probes should be the prefix-collision shape, embedding
	// the target host as a leftmost subdomain of the canary.
	prefixSeen := false
	for _, o := range origins {
		if strings.Contains(o, "."+corsReflectionCanaryHost) && o != corsReflectionCanary {
			prefixSeen = true
		}
	}
	if !prefixSeen {
		t.Errorf("expected a prefix-collision probe like https://<host>.%s; got %v", corsReflectionCanaryHost, origins)
	}
}

func TestCORSReflectionAggressiveConsolidatesMultipleTechniques(t *testing.T) {
	// Server reflects any Origin verbatim AND trusts null. Aggressive
	// mode should produce a single finding listing both techniques in
	// the title; the consolidated detail must mention each.
	srv := httptest.NewServer(reflectorHandler(true))
	defer srv.Close()

	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := CORSReflection{}.Run(ctx, newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(f.Title, "verbatim") {
		t.Errorf("title should list verbatim: %q", f.Title)
	}
	if !strings.Contains(f.Title, "null-origin") {
		t.Errorf("title should list null-origin: %q", f.Title)
	}
	if !strings.Contains(f.Title, "prefix-collision") {
		t.Errorf("title should list prefix-collision: %q", f.Title)
	}
}

func TestCORSReflectionAggressiveCatchesNullOnlyTrust(t *testing.T) {
	// Server only trusts the null origin, not arbitrary ones. The
	// verbatim probe must miss; the aggressive null probe must hit.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// At LevelDefault no finding because verbatim doesn't reflect.
	if fs, err := (CORSReflection{}).Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL)); err != nil {
		t.Fatalf("Run default: %v", err)
	} else if len(fs) != 0 {
		t.Fatalf("default level must not detect null-only trust: %+v", fs)
	}

	// At LevelAggressive the null probe catches it.
	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := (CORSReflection{}).Run(ctx, newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run aggressive: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding at aggressive, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Title, "null-origin") {
		t.Errorf("title should list null-origin: %q", findings[0].Title)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (null + credentials)", findings[0].Severity)
	}
}

func TestCORSReflectionPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewServer(reflectorHandler(true))
	defer srv.Close()

	findings, err := CORSReflection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Target != srv.URL || f.URL != srv.URL {
		t.Errorf("Target/URL = %q/%q, want %q", f.Target, f.URL, srv.URL)
	}
	if f.OWASP == "" || f.Remediation == "" || f.DedupeKey == "" {
		t.Errorf("OWASP/Remediation/DedupeKey must be populated: %+v", f)
	}
	if f.Evidence == nil {
		t.Fatalf("Evidence is nil")
	}
	if f.Evidence.Method != "GET" {
		t.Errorf("Evidence method = %q, want GET", f.Evidence.Method)
	}
	if f.Evidence.Exchange == nil {
		t.Fatalf("Evidence.Exchange is nil")
	}
	if f.Evidence.Exchange.RequestHeaders.Get("Origin") != corsReflectionCanary {
		t.Errorf("evidence exchange should record the probe Origin header; got %v", f.Evidence.Exchange.RequestHeaders)
	}
}

func TestCORSReflectionDedupeKeyStableAndPerHost(t *testing.T) {
	srv := httptest.NewServer(reflectorHandler(true))
	defer srv.Close()

	run := func() string {
		fs, err := CORSReflection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(fs))
		}
		return fs[0].DedupeKey
	}
	a, b := run(), run()
	if a != b {
		t.Errorf("dedupe key drifted across runs: %q vs %q", a, b)
	}
}

func TestCORSReflectionReturnsErrorOnNetworkFailure(t *testing.T) {
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	_, err := CORSReflection{}.Run(context.Background(), c, nil, page.FromURL("http://hyperz-test-no-such-host.invalid"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}

func TestCORSReflectionSkipsUnparseableURL(t *testing.T) {
	// A malformed page URL is not an error condition for this check;
	// returning a finding or surfacing an error would pollute the scan.
	findings, err := CORSReflection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL("::: not a url :::"))
	if err != nil {
		t.Fatalf("unparseable URL should be silently skipped, got error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings on unparseable URL, got %+v", findings)
	}
}
