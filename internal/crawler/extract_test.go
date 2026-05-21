package crawler

import (
	"net/url"
	"reflect"
	"sort"
	"testing"
)

func TestExtractLinksResolvesRelative(t *testing.T) {
	base, _ := url.Parse("http://example.com/page")
	body := []byte(`
		<a href="/abs">x</a>
		<a href="rel">y</a>
		<a href="http://other.example/full">z</a>
		<img src="/img.png">
	`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{
		"http://example.com/abs",
		"http://example.com/img.png",
		"http://example.com/rel",
		"http://other.example/full",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestExtractLinksDropsNonHTTPSchemes(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := []byte(`
		<a href="mailto:a@b">m</a>
		<a href="javascript:void(0)">j</a>
		<a href="ftp://x/y">f</a>
		<a href="http://ok">o</a>
	`)
	got := extractLinks(base, body)
	if len(got) != 1 || got[0] != "http://ok" {
		t.Fatalf("got %v, want [http://ok]", got)
	}
}

func TestExtractLinksStripsFragmentAndDedupes(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := []byte(`
		<a href="/p#one">1</a>
		<a href="/p#two">2</a>
		<a href="/p">3</a>
	`)
	got := extractLinks(base, body)
	if len(got) != 1 || got[0] != "http://example.com/p" {
		t.Fatalf("got %v, want [http://example.com/p]", got)
	}
}

func TestExtractLinksCaseInsensitiveAttrs(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := []byte(`<A HREF='/x'>x</A><SCRIPT SRC="/y.js">`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{"http://example.com/x", "http://example.com/y.js"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractLinksEmptyBody(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	if got := extractLinks(base, nil); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}
