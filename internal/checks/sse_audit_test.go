package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

// sseHandlerConfig drives the synthetic SSE endpoint. The defaults yield
// a correctly-restrictive endpoint (no ACAO, no findings); each toggle
// turns one cross-origin failure mode on so tests can scope to the
// exact case they care about.
type sseHandlerConfig struct {
	// NotSSE switches the Content-Type to application/json so the probe
	// concludes the URL is not actually an SSE endpoint.
	NotSSE bool
	// ACAO is the literal value to return in Access-Control-Allow-Origin.
	// Empty means the header is not set (the safe default).
	ACAO string
	// EchoOrigin returns Access-Control-Allow-Origin equal to the
	// request's Origin header (the classic reflective-CORS bug).
	EchoOrigin bool
	// Credentials sets Access-Control-Allow-Credentials: true.
	Credentials bool
}

func sseServer(t *testing.T, cfg sseHandlerConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.NotSSE {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if cfg.EchoOrigin {
			if o := r.Header.Get("Origin"); o != "" {
				w.Header().Set("Access-Control-Allow-Origin", o)
			}
		} else if cfg.ACAO != "" {
			w.Header().Set("Access-Control-Allow-Origin", cfg.ACAO)
		}
		if cfg.Credentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: ping\ndata: hello\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
}

func TestSSEAuditName(t *testing.T) {
	if got := (SSEAudit{}).Name(); got != "sse-audit" {
		t.Fatalf("Name = %q, want sse-audit", got)
	}
}

func TestSSEAuditLevel(t *testing.T) {
	if got := (SSEAudit{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

func TestSSEAuditSkipsWhenNoEndpointsDiscovered(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pg := page.FromURL(srv.URL + "/")
	pg.Body = []byte(`<html><body>nothing</body></html>`)

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings; got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; nothing to probe", got)
	}
}

func TestSSEAuditDetectsWildcardACAO(t *testing.T) {
	srv := sseServer(t, sseHandlerConfig{ACAO: "*"})
	defer srv.Close()

	// Page is itself the SSE endpoint - simulate that the crawler
	// already fetched it and got back a text/event-stream response.
	pg := page.Page{
		URL:     srv.URL + "/stream",
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/event-stream"}},
	}

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if !strings.Contains(strings.ToLower(f.Title), "any origin") {
		t.Errorf("title = %q, want wildcard wording", f.Title)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if f.CWE != "CWE-942" {
		t.Errorf("CWE = %q, want CWE-942", f.CWE)
	}
}

func TestSSEAuditDetectsReflectedOriginWithCredentials(t *testing.T) {
	srv := sseServer(t, sseHandlerConfig{EchoOrigin: true, Credentials: true})
	defer srv.Close()

	pg := page.Page{
		URL:     srv.URL + "/feed",
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/event-stream"}},
	}

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Title), "reflects") {
		t.Errorf("title = %q, want reflective-CORS wording", f.Title)
	}
}

func TestSSEAuditDetectsWildcardWithCredentials(t *testing.T) {
	srv := sseServer(t, sseHandlerConfig{ACAO: "*", Credentials: true})
	defer srv.Close()

	pg := page.Page{
		URL:     srv.URL + "/stream",
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/event-stream"}},
	}

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(strings.ToLower(findings[0].Title), "spec-illegal") {
		t.Errorf("title = %q, want spec-illegal wording", findings[0].Title)
	}
}

func TestSSEAuditDetectsNullOrigin(t *testing.T) {
	srv := sseServer(t, sseHandlerConfig{ACAO: "null"})
	defer srv.Close()

	pg := page.Page{
		URL:     srv.URL + "/stream",
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/event-stream"}},
	}

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if !strings.Contains(strings.ToLower(findings[0].Title), "null origin") {
		t.Errorf("title = %q, want null-origin wording", findings[0].Title)
	}
}

func TestSSEAuditDoesNotFlagWhenCORSAbsent(t *testing.T) {
	srv := sseServer(t, sseHandlerConfig{}) // no ACAO at all
	defer srv.Close()

	pg := page.Page{
		URL:     srv.URL + "/stream",
		Status:  200,
		Headers: http.Header{"Content-Type": {"text/event-stream"}},
	}

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (CORS not permissive); got %+v", findings)
	}
}

func TestSSEAuditSkipsNonSSEEndpoint(t *testing.T) {
	// Even a permissive ACAO is not an SSE finding when the response
	// isn't actually an event stream. cors-config already covers that.
	srv := sseServer(t, sseHandlerConfig{NotSSE: true, ACAO: "*"})
	defer srv.Close()

	// Discovery comes from a body reference (so we don't already know
	// it's SSE before probing).
	pg := page.FromURL(srv.URL + "/page")
	pg.Body = []byte(`<script>const es = new EventSource("` + srv.URL + `/stream");</script>`)

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (not an SSE endpoint); got %+v", findings)
	}
}

func TestSSEAuditDiscoversFromEventSourceLiteral(t *testing.T) {
	srv := sseServer(t, sseHandlerConfig{ACAO: "*"})
	defer srv.Close()

	pg := page.FromURL(srv.URL + "/app")
	pg.Body = []byte(`<script>const es = new EventSource("` + srv.URL + `/stream");</script>`)

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d: %+v", len(findings), findings)
	}
}

func TestSSEAuditSkipsThirdPartyEndpoint(t *testing.T) {
	// EventSource literal pointing at a different host than the page
	// should not be probed.
	srv := sseServer(t, sseHandlerConfig{ACAO: "*"})
	defer srv.Close()

	pg := page.FromURL("http://app.example.com/")
	pg.Body = []byte(`<script>new EventSource("` + srv.URL + `/stream");</script>`)

	findings, err := SSEAudit{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (third-party host); got %+v", findings)
	}
}

func TestDiscoverSSEEndpoints(t *testing.T) {
	pageURL := mustURL(t, "http://app.example.com/dashboard")
	cases := []struct {
		name    string
		body    string
		headers http.Header
		want    []string
	}{
		{
			name:    "page is itself an SSE endpoint",
			headers: http.Header{"Content-Type": {"text/event-stream"}},
			want:    []string{"http://app.example.com/dashboard"},
		},
		{
			name: "EventSource literal with relative URL",
			body: `<script>const es = new EventSource("/feed");</script>`,
			want: []string{"http://app.example.com/feed"},
		},
		{
			name: "EventSource literal with absolute URL",
			body: `new EventSource('http://app.example.com/events?since=1')`,
			want: []string{"http://app.example.com/events?since=1"},
		},
		{
			name: "dedupe literal + page-is-sse",
			body: `new EventSource("/dashboard")`,
			headers: http.Header{"Content-Type": {"text/event-stream"}},
			want: []string{"http://app.example.com/dashboard"},
		},
		{
			name: "no markers",
			body: `<html><body>hi</body></html>`,
			want: nil,
		},
		{
			name: "ignores non-http schemes",
			body: `new EventSource("ws://app.example.com/events")`,
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pg := page.Page{URL: pageURL.String(), Body: []byte(tc.body), Headers: tc.headers}
			got := discoverSSEEndpoints(pg, pageURL)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestIsEventStream(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"text/event-stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"Text/Event-Stream", true},
		{"text/plain", false},
		{"application/json", false},
		{"", false},
		{"not a real media type", false},
	}
	for _, tc := range cases {
		if got := isEventStream(tc.ct); got != tc.want {
			t.Errorf("isEventStream(%q) = %v, want %v", tc.ct, got, tc.want)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
