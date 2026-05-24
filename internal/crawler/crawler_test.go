package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// mustScope builds a Scope from Config, panicking on error. Tests only.
func mustScope(t *testing.T, cfg scope.Config) *scope.Scope {
	t.Helper()
	s, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return s
}

// seedScope is the common "same-host as seeds, depth N" scope used by most
// of the older tests after Scope replaced Config.SameHost/MaxDepth.
func seedScope(t *testing.T, maxDepth int, seeds ...string) *scope.Scope {
	t.Helper()
	s := mustScope(t, scope.Config{MaxDepth: maxDepth})
	for _, seed := range seeds {
		if u, err := url.Parse(seed); err == nil && u.Hostname() != "" {
			s.AllowHost(u.Hostname())
		}
	}
	return s
}

// linkedSite stands up a tree of HTML pages linked by relative paths:
//
//	/      â†’ /a, /b
//	/a     â†’ /a/x
//	/a/x   â†’ (leaf)
//	/b     â†’ /b/y
//	/b/y   â†’ /b/y/z
//	/b/y/z â†’ (leaf)
func linkedSite(t *testing.T) *httptest.Server {
	t.Helper()
	pages := map[string]string{
		"/":      `<a href="/a">a</a><a href="/b">b</a>`,
		"/a":     `<a href="/a/x">x</a>`,
		"/a/x":   `<p>leaf</p>`,
		"/b":     `<a href="/b/y">y</a>`,
		"/b/y":   `<a href="/b/y/z">z</a>`,
		"/b/y/z": `<p>leaf</p>`,
	}
	mux := http.NewServeMux()
	for path, body := range pages {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, body)
		})
	}
	return httptest.NewServer(mux)
}

func newCrawlerClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:   5 * time.Second,
		UserAgent: "test-crawler",
	})
}

func collectAll(out <-chan page.Page) []string {
	var got []string
	for p := range out {
		got = append(got, p.URL)
	}
	sort.Strings(got)
	return got
}

func stripHost(urls []string) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		if idx := strings.Index(u, "://"); idx >= 0 {
			if slash := strings.Index(u[idx+3:], "/"); slash >= 0 {
				out[i] = u[idx+3+slash:]
				continue
			}
			out[i] = "/"
			continue
		}
		out[i] = u
	}
	return out
}

func TestCrawlDepthZeroOnlyEmitsSeeds(t *testing.T) {
	srv := linkedSite(t)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{Scope: seedScope(t, 0, srv.URL)})
	out := make(chan page.Page, 16)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := collectAll(out)
	if len(got) != 1 {
		t.Fatalf("got %v, want exactly seed URL", got)
	}
}

func TestCrawlReachesAllLinkedPages(t *testing.T) {
	srv := linkedSite(t)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{Scope: seedScope(t, 5, srv.URL)})
	out := make(chan page.Page, 32)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	want := []string{"/", "/a", "/a/x", "/b", "/b/y", "/b/y/z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestCrawlMaxPagesCaps(t *testing.T) {
	srv := linkedSite(t)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{Scope: seedScope(t, 5, srv.URL), MaxPages: 3})
	out := make(chan page.Page, 16)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := collectAll(out)
	if len(got) > 3 {
		t.Fatalf("got %d URLs, want â‰¤3: %v", len(got), got)
	}
}

func TestCrawlSameHostRestrictsToSeeds(t *testing.T) {
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<p>elsewhere</p>`)
	}))
	defer external.Close()

	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<a href="%s/">offsite</a><a href="/inner">on</a>`, external.URL)
	}))
	defer internal.Close()

	// Both servers run on 127.0.0.1; differentiate by binding the scope to
	// the internal server's port so the offsite link is rejected on port,
	// not hostname.
	intURL, _ := url.Parse(internal.URL)
	sc := mustScope(t, scope.Config{MaxDepth: 3, Ports: intURL.Port()})
	sc.AllowHost(intURL.Hostname())
	c := New(newCrawlerClient(), Config{Scope: sc})
	out := make(chan page.Page, 16)
	if err := c.Crawl(context.Background(), []string{internal.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := collectAll(out)
	for _, u := range got {
		if strings.HasPrefix(u, external.URL) {
			t.Errorf("offsite URL leaked: %s", u)
		}
	}
}

func TestCrawlSkipsNonHTMLContent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"links":["/should-not-follow"]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{Scope: seedScope(t, 3, srv.URL)})
	out := make(chan page.Page, 8)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	if !reflect.DeepEqual(got, []string{"/"}) {
		t.Fatalf("got %v, want only the seed", got)
	}
}

func TestCrawlInvokesErrorHandlerOnFetchFailure(t *testing.T) {
	// /bad â†’ 500; the error handler should be called for it (after success
	// on /), but the crawl as a whole still completes without error.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/bad">bad</a>`)
	})
	mux.HandleFunc("/bad", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// /bad returns HTML successfully so it gets emitted; but its body has
		// no links, so it's effectively a leaf. To exercise the error path,
		// use a path that closes the connection abruptly.
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var errs int
	c := New(newCrawlerClient(), Config{Scope: seedScope(t, 3, srv.URL)},
		WithErrorHandler(func(target string, err error) { errs++ }))
	out := make(chan page.Page, 8)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	_ = collectAll(out)
	if errs == 0 {
		t.Fatal("expected error handler to be called at least once")
	}
}

func TestCrawlMarksFailedFetchesAsFetched(t *testing.T) {
	// The crawler emits a Page for URLs it failed to fetch so downstream
	// checks still see the URL. That Page must carry Fetched=true so
	// per-check ensureResponse calls don't re-GET the dead URL and amplify
	// one failure into N "connection refused" events.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/dead">dead</a>`)
	})
	mux.HandleFunc("/dead", func(w http.ResponseWriter, r *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{Scope: seedScope(t, 3, srv.URL)})
	out := make(chan page.Page, 8)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	var deadPage *page.Page
	for p := range out {
		if strings.HasSuffix(p.URL, "/dead") {
			pp := p
			deadPage = &pp
		}
	}
	if deadPage == nil {
		t.Fatal("crawler did not emit a Page for /dead")
	}
	if !deadPage.Fetched {
		t.Errorf("Fetched = false on failed page; want true so checks skip the retry")
	}
	if deadPage.Headers != nil {
		t.Errorf("Headers = %v on failed page; want nil", deadPage.Headers)
	}
}

func TestCrawlDefaultWorkersAndBody(t *testing.T) {
	c := New(newCrawlerClient(), Config{})
	if c.cfg.Workers != 8 {
		t.Errorf("default Workers = %d, want 8", c.cfg.Workers)
	}
	if c.cfg.MaxBodyBytes != defaultMaxBodyBytes {
		t.Errorf("default MaxBodyBytes = %d, want %d", c.cfg.MaxBodyBytes, defaultMaxBodyBytes)
	}
}

func TestCrawlAPIDiscoveryProbesWellKnownPaths(t *testing.T) {
	// Server exposes a tiny HTML page at / and an OpenAPI spec at
	// /openapi.json. With APIDiscovery on, the crawler should fetch the
	// spec from a well-known probe and enqueue every documented operation
	// as a scan target.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<p>home</p>`)
	})
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"openapi":"3.0.0",
			"paths":{
				"/api/users":{"get":{}},
				"/api/users/{id}":{"get":{}}
			}
		}`)
	})
	// Other well-known paths 404 - normal case.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{
		Scope:        seedScope(t, 2, srv.URL),
		APIDiscovery: true,
	})
	out := make(chan page.Page, 64)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	wantContains := []string{"/api/users", "/api/users/1"}
	for _, w := range wantContains {
		found := false
		for _, u := range got {
			if u == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %q in crawl output %v", w, got)
		}
	}
}

func TestCrawlAPIDiscoveryDisabledSkipsNonHTML(t *testing.T) {
	// Same server as above but APIDiscovery=false. The spec endpoint must
	// not contribute any documented operations; only the seed should land.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/openapi.json">spec</a>`)
	})
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openapi":"3.0.0","paths":{"/api/x":{"get":{}}}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{
		Scope:        seedScope(t, 2, srv.URL),
		APIDiscovery: false,
	})
	out := make(chan page.Page, 32)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	for _, u := range got {
		if u == "/api/x" {
			t.Fatalf("APIDiscovery off should not enqueue spec-derived endpoints, got %v", got)
		}
	}
}

func TestCrawlAPIDiscoveryAttachesSpecOpsToEmittedPages(t *testing.T) {
	// The whole point of the wiring: when a spec is parsed, the input
	// inventory it declared for each operation must ride on the Page
	// emitted for that operation's URL. Without this, SinksFor only
	// sees query strings on the URL and forms on HTML, and the params
	// the spec told us about (path / header / json body) are lost.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<p>home</p>`)
	})
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"openapi":"3.0.0",
			"paths":{
				"/items/{id}":{
					"get":{
						"parameters":[
							{"name":"id","in":"path"},
							{"name":"verbose","in":"query"}
						]
					},
					"post":{
						"parameters":[{"name":"id","in":"path"}],
						"requestBody":{
							"content":{
								"application/json":{
									"schema":{"properties":{"title":{"type":"string"}}}
								}
							}
						}
					}
				}
			}
		}`)
	})
	// The crawler will GET each spec-derived URL too; respond cheaply.
	mux.HandleFunc("/items/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{
		Scope:        seedScope(t, 2, srv.URL),
		APIDiscovery: true,
	})
	out := make(chan page.Page, 64)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	var target *page.Page
	for p := range out {
		if strings.HasSuffix(p.URL, "/items/1") {
			pp := p
			target = &pp
		}
	}
	if target == nil {
		t.Fatal("no Page emitted for /items/1")
	}
	if len(target.SpecOps) != 2 {
		t.Fatalf("want 2 SpecOps on /items/1, got %d: %+v", len(target.SpecOps), target.SpecOps)
	}
	methods := map[string]bool{}
	for _, op := range target.SpecOps {
		methods[op.Method] = true
		if !strings.HasSuffix(op.Tpl, "/items/{id}") {
			t.Errorf("op %s missing path template, got Tpl=%q", op.Method, op.Tpl)
		}
	}
	if !methods["GET"] || !methods["POST"] {
		t.Errorf("expected GET and POST SpecOps, got %v", methods)
	}
}

func TestCrawlDedupesAcrossFragments(t *testing.T) {
	// /home is linked from /, /a, /b â†’ must still be emitted only once.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/a">a</a><a href="/b">b</a><a href="/home">h</a>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/home#one">h</a>`)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="/home#two">h</a>`)
	})
	mux.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<p>home</p>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{Scope: seedScope(t, 5, srv.URL)})
	out := make(chan page.Page, 16)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	homeCount := 0
	for _, u := range got {
		if u == "/home" {
			homeCount++
		}
	}
	if homeCount != 1 {
		t.Fatalf("/home emitted %d times, want 1 (got %v)", homeCount, got)
	}
}

// selectPortalSite mimics bWAPP's portal: a single <select name="bug"> whose
// POST to /portal redirects to a per-option destination. Options 1 and 4 are
// "category headers" - the server redirects them back to /portal so the
// walker should drop them as no-ops; the rest land on per-bug pages.
func selectPortalSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/portal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.FormValue("form") != "submit" {
				http.Error(w, "missing form=submit", http.StatusBadRequest)
				return
			}
			dest := "/portal"
			switch r.FormValue("bug") {
			case "2":
				dest = "/bug2"
			case "3":
				dest = "/bug3"
			case "5":
				dest = "/bug5"
			}
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `
			<form action="/portal" method="POST">
				<select name="bug">
					<option value="1">--- category ---</option>
					<option value="2">Bug 2</option>
					<option value="3">Bug 3</option>
					<option value="4">--- category ---</option>
					<option value="5">Bug 5</option>
				</select>
				<button type="submit" name="form" value="submit">Hack</button>
			</form>
		`)
	})
	for _, p := range []string{"/bug2", "/bug3", "/bug5"} {
		p := p
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<p>%s</p>", p)
		})
	}
	return httptest.NewServer(mux)
}

func TestCrawlPolluteWalksSelectForm(t *testing.T) {
	srv := selectPortalSite(t)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{
		Scope:   seedScope(t, 2, srv.URL),
		Pollute: true,
	})
	out := make(chan page.Page, 32)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/portal"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	want := []string{"/bug2", "/bug3", "/bug5", "/portal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestCrawlPolluteOffSkipsSelectForm(t *testing.T) {
	srv := selectPortalSite(t)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{
		Scope: seedScope(t, 2, srv.URL),
	})
	out := make(chan page.Page, 32)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/portal"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	if !reflect.DeepEqual(got, []string{"/portal"}) {
		t.Fatalf("got %v, want only [/portal]", got)
	}
}

func TestCrawlPolluteSkipsFormsWithVisibleInputs(t *testing.T) {
	// A form with a visible text input alongside the select is almost
	// certainly a real submission (search, comment, ...), not navigation.
	// The walker must not POST it even when --pollute is on.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<form action="/danger" method="POST">
				<input type="text" name="q">
				<select name="filter">
					<option value="a">A</option>
					<option value="b">B</option>
				</select>
				<button type="submit">Go</button>
			</form>
		`)
	})
	mux.HandleFunc("/danger", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("/danger should NOT be POSTed by select-form walker")
		http.Redirect(w, r, "/should-not-appear", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(newCrawlerClient(), Config{
		Scope:   seedScope(t, 2, srv.URL),
		Pollute: true,
	})
	out := make(chan page.Page, 32)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	if !reflect.DeepEqual(got, []string{"/"}) {
		t.Fatalf("got %v, want only [/]", got)
	}
}
