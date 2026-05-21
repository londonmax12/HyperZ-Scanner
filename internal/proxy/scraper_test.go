package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScrapeParsesMixedFormats stands up two fake "proxy list" sources, one
// in plain-text and one with extra junk, and verifies that:
//   - host:port pairs are extracted from both
//   - duplicates across sources are deduped
//   - results are returned as parsed *url.URL with http:// scheme
//   - a single-source failure doesn't abort the scrape
func TestScrapeParsesMixedFormats(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Join([]string{
			"1.1.1.1:8080",
			"2.2.2.2:3128",
			"3.3.3.3:80",
			"",
		}, "\n"))
	}))
	defer plain.Close()

	noisy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Duplicate of plain's first entry + a new one wrapped in junk.
		fmt.Fprint(w, "# header line\nproxy=1.1.1.1:8080 ssl=true\n<li>4.4.4.4:1080 (us)</li>\n")
	}))
	defer noisy.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()

	var sourceErrors int
	urls, err := Scrape(context.Background(), ScrapeConfig{
		Sources:   []string{plain.URL, noisy.URL, dead.URL},
		UserAgent: "test",
		OnError: func(src string, err error) {
			sourceErrors++
		},
	})
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if sourceErrors != 1 {
		t.Fatalf("expected 1 source error, got %d", sourceErrors)
	}

	got := map[string]bool{}
	for _, u := range urls {
		got[u.String()] = true
	}
	want := []string{
		"http://1.1.1.1:8080",
		"http://2.2.2.2:3128",
		"http://3.3.3.3:80",
		"http://4.4.4.4:1080",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %s in result %v", w, got)
		}
	}
	if len(urls) != len(want) {
		t.Fatalf("got %d unique proxies, want %d (%v)", len(urls), len(want), got)
	}
}

func TestLoadParsesSchemesAndDedupes(t *testing.T) {
	urls, err := Load([]string{
		"http://1.1.1.1:8080",
		"socks5://2.2.2.2:1080",
		"3.3.3.3:3128",   // bare → http://
		"1.1.1.1:8080",   // dup of first (after scheme inference)
	}, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(urls) != 3 {
		t.Fatalf("got %d urls, want 3: %v", len(urls), urls)
	}
}
