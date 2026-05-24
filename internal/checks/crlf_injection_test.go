package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestCRLFInjectionName(t *testing.T) {
	if got := (CRLFInjection{}).Name(); got != "crlf-injection" {
		t.Fatalf("Name = %q, want crlf-injection", got)
	}
}

func TestCRLFInjectionLevel(t *testing.T) {
	if got := (CRLFInjection{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// vulnCRLFHandler simulates a response-splitting bug. It URL-decodes the
// `next` query parameter and writes it verbatim into a Location header
// line via the raw socket - http.ResponseWriter would refuse a CR/LF in
// a header value, so the test has to hijack the connection to faithfully
// reproduce the real-world vulnerability.
//
// terminator selects how the handler ends the (still attacker-supplied)
// Location header: "\r\n" matches a server that uses Printf with %s and
// the parser splits the response cleanly; "\n" matches a server whose
// filter strips \r but leaves \n alone.
func vulnCRLFHandler(t *testing.T, terminator string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatalf("test server does not support hijacking")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close()
		// We deliberately splice `next` into the Location line followed
		// by `terminator`. If `next` contained CR/LF, the bytes hit the
		// wire and the response parser sees additional header lines.
		fmt.Fprintf(bufrw, "HTTP/1.1 302 Found\r\nLocation: %s%sContent-Length: 0\r\n\r\n", next, terminator)
		bufrw.Flush()
	})
}

func TestCRLFInjectionDetectsCRLFInQueryParam(t *testing.T) {
	srv := httptest.NewServer(vulnCRLFHandler(t, "\r\n"))
	defer srv.Close()

	// A query param has to exist on p.URL so SinksFor surfaces it as a sink.
	target := srv.URL + "/redirect?next=home"

	findings, err := CRLFInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
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
	if f.CWE != "CWE-113" {
		t.Errorf("CWE = %q, want CWE-113", f.CWE)
	}
	if !strings.Contains(f.Title, "next") {
		t.Errorf("Title should name the vulnerable param: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "X-Hyperz-CRLF") {
		t.Errorf("Detail should mention the smuggled header: %q", f.Detail)
	}
	if f.OWASP == "" || f.Remediation == "" {
		t.Errorf("OWASP/Remediation must be populated: %+v", f)
	}
	if f.DedupeKey == "" {
		t.Errorf("DedupeKey must be set")
	}
}

func TestCRLFInjectionDetectsLFOnlySplit(t *testing.T) {
	// LF-only terminator: server filtered \r but the parser still treats
	// \n as a line break. The CRLF probe variant won't trigger (the \r
	// would have been stripped), but the LF-only fallback should.
	//
	// The handler strips the literal \r\n SEQUENCE - a common naive
	// blocklist - but lets a bare \n through. The CRLF probe is
	// neutralized (\r\n → ""), while the LF-only probe survives and
	// reaches the wire intact.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := strings.ReplaceAll(r.URL.Query().Get("next"), "\r\n", "")
		hj := w.(http.Hijacker)
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close()
		fmt.Fprintf(bufrw, "HTTP/1.1 302 Found\nLocation: %s\nContent-Length: 0\n\n", next)
		bufrw.Flush()
	}))
	defer srv.Close()

	target := srv.URL + "/redirect?next=home"
	findings, err := CRLFInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding via LF-only path, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Detail, "LF only") {
		t.Errorf("Detail should label the LF-only variant: %q", findings[0].Detail)
	}
}

func TestCRLFInjectionNoFalsePositiveOnSafeHandler(t *testing.T) {
	// A handler that ignores the input entirely. No echo into headers,
	// no canary in the response - no finding.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()

	target := srv.URL + "/page?next=home"
	findings, err := CRLFInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCRLFInjectionNoFalsePositiveOnFilteredHandler(t *testing.T) {
	// A handler that DOES use the input in a header but properly strips
	// CR/LF. The response carries the value but no smuggled header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		clean := strings.NewReplacer("\r", "", "\n", "").Replace(next)
		w.Header().Set("Location", "/"+clean)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	target := srv.URL + "/r?next=home"
	findings, err := CRLFInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCRLFInjectionRespectsScope(t *testing.T) {
	// Out-of-scope target: the check must NOT send a probe even when a
	// vulnerable server is reachable. The hit counter on the server
	// stays at zero.
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
	target := srv.URL + "/r?next=home"
	findings, err := CRLFInjection{}.Run(context.Background(), newTestClient(t), sc, page.FromURL(target))
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

func TestCRLFInjectionEvidenceCapturesExchange(t *testing.T) {
	srv := httptest.NewServer(vulnCRLFHandler(t, "\r\n"))
	defer srv.Close()

	target := srv.URL + "/redirect?next=home"
	findings, err := CRLFInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings")
	}
	f := findings[0]
	if f.Evidence == nil || f.Evidence.Exchange == nil {
		t.Fatalf("Evidence/Exchange must be set: %+v", f.Evidence)
	}
	ex := f.Evidence.Exchange
	if ex.Status != http.StatusFound {
		t.Errorf("Exchange.Status = %d, want 302", ex.Status)
	}
	if ex.URL == "" || !strings.Contains(ex.URL, "next=") {
		t.Errorf("Exchange.URL should carry the probed param: %q", ex.URL)
	}
	// The smuggled header must be visible in the captured response
	// headers - that's the evidence the reader needs to confirm the bug.
	if ex.ResponseHeaders.Get(crlfCanaryHeader) == "" {
		t.Errorf("Exchange.ResponseHeaders should contain %s: %v", crlfCanaryHeader, ex.ResponseHeaders)
	}
}

func TestCRLFInjectionEmptySinksReturnsNothing(t *testing.T) {
	// A page with no params and no forms produces no sinks. The check
	// must not panic and must return empty findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	findings, err := CRLFInjection{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on no-sink page, got %d", len(findings))
	}
}

func TestCRLFSepLabel(t *testing.T) {
	cases := []struct {
		sep, want string
	}{
		{"\r\n", "CRLF (\\r\\n)"},
		{"\n", "LF only (\\n)"},
		{"\r", "CR only (\\r)"},
	}
	for _, tc := range cases {
		if got := crlfSepLabel(tc.sep); got != tc.want {
			t.Errorf("crlfSepLabel(%q) = %q, want %q", tc.sep, got, tc.want)
		}
	}
	// Unicode forms fall through to the U+XXXX printer.
	got := crlfSepLabel("嘊")
	if !strings.Contains(got, "U+560A") {
		t.Errorf("crlfSepLabel(unicode) = %q, want U+560A label", got)
	}
}
