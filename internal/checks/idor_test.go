package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestIDORName(t *testing.T) {
	if got := (&IDOR{}).Name(); got != "idor" {
		t.Fatalf("Name = %q, want idor", got)
	}
}

func TestIDORLevel(t *testing.T) {
	if got := (&IDOR{}).Level(); got != LevelAggressive {
		t.Fatalf("Level = %v, want aggressive", got)
	}
}

// vulnIDORHandler simulates an endpoint that returns each user's record
// when given a small numeric user_id but rejects obviously-out-of-range
// IDs as 404. This lets the control probe (999999999999) reject while
// the tampered probes (41, 43) still find user content - the canonical
// IDOR signal idorJudge fires on.
//
// reqCount lets tests assert the probe count came in under the budget.
func vulnIDORHandler(reqCount *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(reqCount, 1)
		raw := r.URL.Query().Get("user_id")
		id, err := strconv.Atoi(raw)
		if err != nil || id < 0 || id > 100000 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": "user not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body := fmt.Sprintf(
			`{"id": %d, "first_name": "User%d", "email": "user%d@example.test", "address_line_1": "%d Main Street"}`,
			id, id, id, id,
		)
		// Pad with a stable templated tail so Similarity scores baseline-
		// vs-tampered on the differing record body in the middle rather
		// than tripping on length-ratio alone.
		body += strings.Repeat(" filler", 64)
		_, _ = w.Write([]byte(body))
	})
}

func TestIDORDetectsVulnerableNumericParam(t *testing.T) {
	var reqs int32
	srv := httptest.NewServer(vulnIDORHandler(&reqs))
	defer srv.Close()

	p := page.Page{URL: srv.URL + "/profile?user_id=42"}
	findings, err := (&IDOR{}).Run(context.Background(), newTestClient(t), nil, p)
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
	if f.CWE != "CWE-639" {
		t.Errorf("CWE = %q, want CWE-639", f.CWE)
	}
	if !strings.Contains(f.Title, "user_id") {
		t.Errorf("Title should name the param: %q", f.Title)
	}
	if !strings.Contains(f.Detail, patternNameNumeric) {
		t.Errorf("Detail should name the numeric pattern: %q", f.Detail)
	}
	if f.Evidence == nil || f.Evidence.Exchange == nil {
		t.Fatalf("Evidence/Exchange missing: %+v", f.Evidence)
	}
	// We classify a JSON body with name/email fields as PII -> high
	// confidence.
	confidenceBullet := ""
	for _, d := range f.Details {
		if strings.HasPrefix(d, "confidence:") {
			confidenceBullet = d
		}
	}
	if !strings.Contains(confidenceBullet, idorConfidenceHigh) {
		t.Errorf("expected high confidence (PII markers in tampered body); got %q", confidenceBullet)
	}
	// At most 8 sinks * 5 probes = 40; vulnerable param breaks out
	// after first tampered hit so actual probes should be small.
	if reqs > 10 {
		t.Errorf("probed %d times for one vulnerable param, want fewer", reqs)
	}
}

// safeIDORHandler simulates a backend that validates authorization
// against a fixed "session" - only user_id=42 returns content; anything
// else (control or tampered) returns 403. No IDOR signal.
func safeIDORHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("user_id")
		if raw != "42" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error": "forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body := `{"id": 42, "first_name": "Alice", "email": "alice@example.test"}`
		body += strings.Repeat(" filler", 64)
		_, _ = w.Write([]byte(body))
	})
}

func TestIDORDoesNotFireOnAuthorizedEndpoint(t *testing.T) {
	srv := httptest.NewServer(safeIDORHandler())
	defer srv.Close()

	p := page.Page{URL: srv.URL + "/profile?user_id=42"}
	findings, err := (&IDOR{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on safe handler, got %d: %+v", len(findings), findings)
	}
}

// spaFallbackHandler simulates a single-page app that returns the same
// HTML shell for any URL - client-side routing means the server never
// looks at user_id. Baseline ~ control ~ tampered, so idorJudge should
// suppress the finding.
func spaFallbackHandler() http.Handler {
	shell := `<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>`
	shell += strings.Repeat(" filler", 64)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(shell))
	})
}

func TestIDORDoesNotFireOnSPAFallback(t *testing.T) {
	srv := httptest.NewServer(spaFallbackHandler())
	defer srv.Close()

	p := page.Page{URL: srv.URL + "/profile?user_id=42"}
	findings, err := (&IDOR{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on SPA fallback, got %d: %+v", len(findings), findings)
	}
}

// publicResourceHandler simulates a public endpoint that returns the
// same content for any ID - e.g. a blog post page rendered for any
// post_id without auth. Baseline ~ control, so we should suppress.
func publicResourceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		body := `<article><h1>Public Article</h1><p>Always the same content.</p></article>`
		body += strings.Repeat(" filler", 64)
		_, _ = w.Write([]byte(body))
	})
}

func TestIDORDoesNotFireOnPublicResource(t *testing.T) {
	srv := httptest.NewServer(publicResourceHandler())
	defer srv.Close()

	p := page.Page{URL: srv.URL + "/post?post_id=42"}
	findings, err := (&IDOR{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on public resource, got %d: %+v", len(findings), findings)
	}
}

// genericFallback200Handler simulates a backend that returns the seed
// user's record for user_id=42 (baseline) but a generic 200 "no such
// record" page for any other ID. Baseline diverges from tampered (real
// content vs generic page) but tampered ~ control (both get the same
// generic page) - authorized behaviour, not IDOR.
func genericFallback200Handler() http.Handler {
	generic := `{"error": "record not visible"}` + strings.Repeat(" filler", 64)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("user_id")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if raw == "42" {
			body := `{"id": 42, "first_name": "Alice", "email": "alice@example.test"}`
			body += strings.Repeat(" filler", 64)
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(generic))
	})
}

func TestIDORDoesNotFireOnGenericNonSeedFallback(t *testing.T) {
	srv := httptest.NewServer(genericFallback200Handler())
	defer srv.Close()

	p := page.Page{URL: srv.URL + "/profile?user_id=42"}
	findings, err := (&IDOR{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when control ~ tampered, got %d: %+v", len(findings), findings)
	}
}

func TestIDORSkipsNonIdentifierParams(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body := fmt.Sprintf("results for %s", r.URL.Query().Get("q"))
		body += strings.Repeat(" filler", 64)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	p := page.Page{URL: srv.URL + "/search?q=alpha"}
	findings, err := (&IDOR{}).Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on denylisted param, got %d: %+v", len(findings), findings)
	}
}

func TestIDORCorpusSurvivesAcrossRuns(t *testing.T) {
	// Feed three pages with same-shape order_ref values through the
	// same *IDOR instance and confirm the corpus learned the shape.
	idor := &IDOR{}
	for _, val := range []string{"ORD-A12B3C", "ORD-B47K9P"} {
		p := page.Page{URL: "https://example.test/orders?order_ref=" + val}
		_, _ = idor.Run(context.Background(), newTestClient(t), nil, p)
	}
	// A third value under a different param closes the distinct-param
	// gate.
	p := page.Page{URL: "https://example.test/purchases?purchase_ref=ORD-Z99X1M"}
	_, _ = idor.Run(context.Background(), newTestClient(t), nil, p)

	learned := idor.corpus.LearnedPatterns()
	wantName := "learned:AAA-A99A9A"
	for _, p := range learned {
		if p.Name == wantName {
			return
		}
	}
	t.Errorf("expected learned pattern %q, got %v", wantName, learnedNames(learned))
}
