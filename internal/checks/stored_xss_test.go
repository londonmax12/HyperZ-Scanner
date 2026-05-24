package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestStoredXSSName(t *testing.T) {
	if got := (&StoredXSS{}).Name(); got != "stored-xss" {
		t.Fatalf("Name = %q, want stored-xss", got)
	}
}

func TestStoredXSSLevel(t *testing.T) {
	if got := (&StoredXSS{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

func TestStoredXSSRunReturnsNothing(t *testing.T) {
	// Run must not double-fire what Plant/Detect produce in two-phase mode.
	// A single-phase invocation against a vulnerable target returns nil so
	// older scanner code paths can register the check without polluting
	// their output with half-formed findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<svg onload=alert(1)>hpzc000000000000</svg>`))
	}))
	defer srv.Close()

	c := &StoredXSS{}
	got, err := c.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Run returned %d findings; want 0 (Plant/Detect carry the verdict in two-phase mode)", len(got))
	}
}

// storedXSSServer simulates an application that stores user input on
// POST and renders it on GET. It is the minimum surface to drive the
// full plant->detect flow: one read URL with a form, one write URL
// that records the value, and the same read URL re-rendering it.
type storedXSSServer struct {
	mu       sync.Mutex
	comments []string
	// hits counts how many times each path was requested across the
	// whole test; useful for asserting cross-page plant dedupe.
	hits map[string]*atomic.Int64
}

func newStoredXSSServer() *storedXSSServer {
	return &storedXSSServer{hits: map[string]*atomic.Int64{}}
}

func (s *storedXSSServer) tick(path string) {
	s.mu.Lock()
	if s.hits[path] == nil {
		s.hits[path] = &atomic.Int64{}
	}
	c := s.hits[path]
	s.mu.Unlock()
	c.Add(1)
}

func (s *storedXSSServer) count(path string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.hits[path]; ok {
		return c.Load()
	}
	return 0
}

func (s *storedXSSServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		s.tick("/post")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var b strings.Builder
		b.WriteString(`<html><body><h1>Post</h1>`)
		b.WriteString(`<form method="POST" action="/comments"><input name="body" type="text"><button>Submit</button></form>`)
		b.WriteString(`<ul>`)
		s.mu.Lock()
		for _, c := range s.comments {
			fmt.Fprintf(&b, `<li>%s</li>`, c)
		}
		s.mu.Unlock()
		b.WriteString(`</ul></body></html>`)
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/comments", func(w http.ResponseWriter, r *http.Request) {
		s.tick("/comments")
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body := r.PostFormValue("body")
		s.mu.Lock()
		s.comments = append(s.comments, body)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// pageWithForm builds a page.Page that mirrors what the crawler would
// hand the check after fetching pageURL: the page itself plus a POST
// form whose action targets actionURL with one text input named "body".
// Plant uses SinksFor over this artifact, so the test does not need to
// spin up the crawler.
func pageWithForm(pageURL, actionURL string) page.Page {
	return page.Page{
		URL: pageURL,
		Forms: []page.Form{
			{
				Method: http.MethodPost,
				Action: actionURL,
				Inputs: []page.FormInput{
					{Name: "body", Type: "text"},
				},
			},
		},
		Fetched: true,
	}
}

// fetchDetect re-fetches u and stuffs the response into a page.Page
// the way the scanner's phase-2 fetcher would. Keeps the test
// independent of the scanner package so failures here pin behaviour to
// StoredXSS alone.
func fetchDetect(t *testing.T, u string) page.Page {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("fetchDetect %s: %v", u, err)
	}
	defer resp.Body.Close()
	body := make([]byte, 0)
	buf := make([]byte, 8192)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return page.Page{
		URL:     u,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    body,
		Fetched: true,
	}
}

func TestStoredXSSPlantThenDetectFiresHighFinding(t *testing.T) {
	srv := httptest.NewServer(newStoredXSSServer().handler())
	defer srv.Close()

	c := &StoredXSS{}
	client := newTestClient(t)

	// Phase 1: plant via the form on /post.
	if _, err := c.Plant(context.Background(), client, nil, pageWithForm(srv.URL+"/post", srv.URL+"/comments")); err != nil {
		t.Fatalf("Plant: %v", err)
	}

	// Phase 2: re-fetch /post (the page that renders stored comments)
	// and hand the response to Detect.
	got, err := c.Detect(context.Background(), client, nil, fetchDetect(t, srv.URL+"/post"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79", f.CWE)
	}
	if !strings.Contains(f.Title, `"body"`) {
		t.Errorf("Title should name the sink param body: %q", f.Title)
	}
	if !strings.Contains(f.Detail, srv.URL+"/post") {
		t.Errorf("Detail should reference the detect URL %s: %q", srv.URL+"/post", f.Detail)
	}
	if !strings.Contains(f.Detail, srv.URL+"/comments") {
		t.Errorf("Detail should reference the plant URL %s/comments: %q", srv.URL, f.Detail)
	}
	if f.Target != srv.URL+"/comments" {
		t.Errorf("Target = %q, want %s/comments (the plant URL)", f.Target, srv.URL)
	}
	if f.URL != srv.URL+"/post" {
		t.Errorf("URL = %q, want %s/post (the detect URL)", f.URL, srv.URL)
	}
	if f.DedupeKey == "" {
		t.Error("DedupeKey must be set so duplicate detections collapse")
	}
}

func TestStoredXSSNoFindingWhenStorageEncodes(t *testing.T) {
	// Server that stores input but HTML-encodes on render. The plant
	// canary is in the body but the breakout bytes are not, so Detect
	// must stay silent: the storage path is safe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/post":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			// Render the canary out of a payload-shaped value, but
			// strip the angle brackets so no breakout survives. The
			// canary in isolation is still observable but it's not
			// exploitable.
			_, _ = w.Write([]byte(`<html><body>hpzc000000000000</body></html>`))
		}
	}))
	defer srv.Close()

	c := &StoredXSS{}
	// Pre-seed a planted record by calling recordPlant directly with a
	// canary that the server intentionally renders. This bypasses the
	// HTTP plant so the test focuses on Detect's encoding-vs-breakout
	// discriminator, not on what the demo server does with the POST.
	c.recordPlant("hpzc000000000000", &storedXSSPlant{
		sink:        sinkKey{method: "POST", url: srv.URL + "/comments", loc: LocForm, name: "body"},
		payload:     `<svg onload=alert(1)>hpzc000000000000</svg>`,
		payloadName: "html-text-svg",
		payloadCtx:  "HTML text",
		plantURL:    srv.URL + "/comments",
	})

	got, err := c.Detect(context.Background(), newTestClient(t), nil, fetchDetect(t, srv.URL+"/post"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 findings (canary present but breakout encoded), got %d: %+v", len(got), got)
	}
}

func TestStoredXSSPerSinkDedupeAcrossPages(t *testing.T) {
	srv := httptest.NewServer(newStoredXSSServer().handler())
	defer srv.Close()

	c := &StoredXSS{}
	client := newTestClient(t)

	// Same form discovered on two different crawler pages. The form's
	// (method, action, loc, name) is identical, so Plant must consider
	// it one attack surface and submit exactly the curated payload
	// family once - not once per crawl page.
	for _, pageURL := range []string{srv.URL + "/post/1", srv.URL + "/post/2"} {
		if _, err := c.Plant(context.Background(), client, nil, pageWithForm(pageURL, srv.URL+"/comments")); err != nil {
			t.Fatalf("Plant(%s): %v", pageURL, err)
		}
	}

	want := len(storedXSSPayloads)
	c.mu.Lock()
	got := len(c.canaries)
	c.mu.Unlock()
	if got != want {
		t.Fatalf("planted %d canaries across 2 pages with the same sink; want exactly %d (per-sink dedupe broken)", got, want)
	}
}

func TestStoredXSSDetectURLsHarvestsSameOriginLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body>
			<a href="/thanks">view your post</a>
			<a href="https://evil.example.com/x">offsite</a>
			<form action="/another"></form>
			<meta http-equiv="refresh" content="0; url=/redirect">
		</body></html>`))
	}))
	defer srv.Close()

	c := &StoredXSS{}
	c.absorbDetectURLs(srv.URL+"/comments", "", []byte(`<a href="/thanks">x</a><form action="/another"></form><a href="https://evil.example.com/x">y</a><meta http-equiv="refresh" content="0; url=/redirect">`))

	urls := c.DetectURLs()
	got := map[string]bool{}
	for _, u := range urls {
		got[u] = true
	}

	mustHave := []string{
		srv.URL + "/thanks",
		srv.URL + "/another",
		srv.URL + "/redirect",
	}
	for _, want := range mustHave {
		if !got[want] {
			t.Errorf("DetectURLs missing %s; got %v", want, urls)
		}
	}
	for u := range got {
		if strings.Contains(u, "evil.example.com") {
			t.Errorf("DetectURLs leaked cross-origin URL %s; only same-origin links should be harvested", u)
		}
	}
}

func TestStoredXSSDetectURLsAbsorbsLocationHeader(t *testing.T) {
	c := &StoredXSS{}
	c.absorbDetectURLs("http://example.test/comments", "/thanks", nil)

	urls := c.DetectURLs()
	if len(urls) != 1 || urls[0] != "http://example.test/thanks" {
		t.Fatalf("Location header not absorbed: got %v", urls)
	}
}

func TestStoredXSSDetectDedupesAcrossPages(t *testing.T) {
	// Two detect pages that both render the same canary should fire
	// exactly one finding, not two: the underlying sink is a single
	// attack surface.
	c := &StoredXSS{}
	c.recordPlant("hpzc111111111111", &storedXSSPlant{
		sink:        sinkKey{method: "POST", url: "http://x/comments", loc: LocForm, name: "body"},
		payload:     `<svg onload=alert(1)>hpzc111111111111</svg>`,
		payloadName: "html-text-svg",
		payloadCtx:  "HTML text",
		plantURL:    "http://x/comments",
	})

	body := []byte(`<html><body><svg onload=alert(1)>hpzc111111111111</svg></body></html>`)
	page1 := page.Page{URL: "http://x/post/1", Body: body, Fetched: true, Status: 200}
	page2 := page.Page{URL: "http://x/post/2", Body: body, Fetched: true, Status: 200}

	got1, err := c.Detect(context.Background(), newTestClient(t), nil, page1)
	if err != nil {
		t.Fatalf("Detect(page1): %v", err)
	}
	got2, err := c.Detect(context.Background(), newTestClient(t), nil, page2)
	if err != nil {
		t.Fatalf("Detect(page2): %v", err)
	}
	if len(got1) != 1 {
		t.Fatalf("expected 1 finding on first detect page, got %d", len(got1))
	}
	if len(got2) != 0 {
		t.Fatalf("expected 0 findings on second detect page (same sink already fired), got %d", len(got2))
	}
}

func TestStoredXSSScopeBlocksOutOfScopePlant(t *testing.T) {
	// A form whose action points to a host the scope rejects must not
	// be planted, even though SinksFor would otherwise list it.
	srv := httptest.NewServer(newStoredXSSServer().handler())
	defer srv.Close()

	// Scope only allows example.invalid; srv.URL is in 127.0.0.1 range
	// so every sink derived from pageWithForm(srv.URL) falls out.
	sc, err := scope.New(scope.Config{Hosts: []string{"example.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}

	c := &StoredXSS{}
	if _, err := c.Plant(context.Background(), newTestClient(t), sc, pageWithForm(srv.URL+"/post", srv.URL+"/comments")); err != nil {
		t.Fatalf("Plant: %v", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if n := len(c.canaries); n != 0 {
		t.Fatalf("planted %d canaries against out-of-scope target; want 0", n)
	}
}
