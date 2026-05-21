package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/londonball/hyperz/internal/httpclient"
)

// linkedSite stands up a tree of HTML pages linked by relative paths:
//
//	/      → /a, /b
//	/a     → /a/x
//	/a/x   → (leaf)
//	/b     → /b/y
//	/b/y   → /b/y/z
//	/b/y/z → (leaf)
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

func collectAll(out <-chan string) []string {
	var got []string
	for u := range out {
		got = append(got, u)
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

	c := New(newCrawlerClient(), Config{MaxDepth: 0})
	out := make(chan string, 16)
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

	c := New(newCrawlerClient(), Config{MaxDepth: 5})
	out := make(chan string, 32)
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

	c := New(newCrawlerClient(), Config{MaxDepth: 5, MaxPages: 3})
	out := make(chan string, 16)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := collectAll(out)
	if len(got) > 3 {
		t.Fatalf("got %d URLs, want ≤3: %v", len(got), got)
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

	c := New(newCrawlerClient(), Config{MaxDepth: 3, SameHost: true})
	out := make(chan string, 16)
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

	c := New(newCrawlerClient(), Config{MaxDepth: 3})
	out := make(chan string, 8)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	got := stripHost(collectAll(out))
	if !reflect.DeepEqual(got, []string{"/"}) {
		t.Fatalf("got %v, want only the seed", got)
	}
}

func TestCrawlInvokesErrorHandlerOnFetchFailure(t *testing.T) {
	// /bad → 500; the error handler should be called for it (after success
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
	c := New(newCrawlerClient(), Config{MaxDepth: 3},
		WithErrorHandler(func(target string, err error) { errs++ }))
	out := make(chan string, 8)
	if err := c.Crawl(context.Background(), []string{srv.URL + "/"}, out); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	_ = collectAll(out)
	if errs == 0 {
		t.Fatal("expected error handler to be called at least once")
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

func TestCrawlDedupesAcrossFragments(t *testing.T) {
	// /home is linked from /, /a, /b → must still be emitted only once.
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

	c := New(newCrawlerClient(), Config{MaxDepth: 5})
	out := make(chan string, 16)
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
