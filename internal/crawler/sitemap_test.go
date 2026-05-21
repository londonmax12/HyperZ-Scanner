package crawler

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseSitemapURLSet(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/a</loc></url>
  <url><loc>https://example.com/b</loc></url>
  <url><loc></loc></url>
</urlset>`
	urls, nested, err := parseSitemap(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseSitemap: %v", err)
	}
	sort.Strings(urls)
	want := []string{"https://example.com/a", "https://example.com/b"}
	if !reflect.DeepEqual(urls, want) {
		t.Fatalf("urls = %v, want %v", urls, want)
	}
	if len(nested) != 0 {
		t.Fatalf("nested = %v, want none", nested)
	}
}

func TestParseSitemapIndex(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sm1.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sm2.xml</loc></sitemap>
</sitemapindex>`
	urls, nested, err := parseSitemap(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseSitemap: %v", err)
	}
	if len(urls) != 0 {
		t.Fatalf("urls = %v, want none", urls)
	}
	sort.Strings(nested)
	want := []string{"https://example.com/sm1.xml", "https://example.com/sm2.xml"}
	if !reflect.DeepEqual(nested, want) {
		t.Fatalf("nested = %v, want %v", nested, want)
	}
}

func TestParseSitemapMalformed(t *testing.T) {
	_, _, err := parseSitemap(strings.NewReader("<not-xml"))
	if err == nil {
		t.Fatal("expected error on malformed XML")
	}
}
