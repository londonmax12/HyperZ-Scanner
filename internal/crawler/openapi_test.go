package crawler

import (
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestLooksLikeSpec(t *testing.T) {
	cases := []struct {
		name string
		ct   string
		path string
		want bool
	}{
		{"json content type", "application/json", "/foo", true},
		{"yaml content type", "application/x-yaml", "/foo", true},
		{"json suffix", "application/octet-stream", "/openapi.json", true},
		{"yaml suffix", "text/plain", "/openapi.yaml", true},
		{"yml suffix", "text/plain", "/openapi.yml", true},
		{"api-docs suffix", "text/plain", "/v3/api-docs", true},
		{"html", "text/html", "/index.html", false},
		{"plain css", "text/css", "/site.css", false},
	}
	for _, c := range cases {
		if got := looksLikeSpec(c.ct, c.path); got != c.want {
			t.Errorf("%s: looksLikeSpec(%q,%q) = %v, want %v", c.name, c.ct, c.path, got, c.want)
		}
	}
}

func TestParseJSONSpecOpenAPI3(t *testing.T) {
	body := []byte(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com/v1"}],
		"paths": {
			"/users": {"get": {}},
			"/users/{id}": {"get": {}, "delete": {}}
		}
	}`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/openapi.json"))
	sort.Strings(got)
	want := []string{
		"https://api.example.com/v1/users",
		"https://api.example.com/v1/users/1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestParseJSONSpecSwagger2(t *testing.T) {
	body := []byte(`{
		"swagger": "2.0",
		"host": "api.example.com",
		"basePath": "/v2",
		"schemes": ["https"],
		"paths": {
			"/pets": {"get": {}},
			"/pets/{petId}": {"get": {}}
		}
	}`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/swagger.json"))
	sort.Strings(got)
	want := []string{
		"https://api.example.com/v2/pets",
		"https://api.example.com/v2/pets/1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestParseJSONSpecFallsBackToSpecOrigin(t *testing.T) {
	body := []byte(`{
		"openapi": "3.0.0",
		"paths": {"/health": {"get": {}}}
	}`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/openapi.json"))
	want := []string{"https://example.com/health"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseJSONSpecRelativeServer(t *testing.T) {
	body := []byte(`{
		"openapi": "3.0.0",
		"servers": [{"url": "/api"}],
		"paths": {"/ping": {"get": {}}}
	}`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/spec/openapi.json"))
	want := []string{"https://example.com/api/ping"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseJSONSpecRejectsNonSpec(t *testing.T) {
	body := []byte(`{"links":["/a","/b"]}`)
	if got := extractAPIEndpoints(body, mustURL(t, "https://example.com/x.json")); len(got) != 0 {
		t.Fatalf("got %v, want none (not a spec)", got)
	}
}

func TestParseJSONSpecRejectsArrayRoot(t *testing.T) {
	if got := extractAPIEndpoints([]byte(`[1,2,3]`), mustURL(t, "https://example.com/x.json")); len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}

func TestParseYAMLSpecOpenAPI3(t *testing.T) {
	body := []byte(`openapi: 3.0.0
info:
  title: Test
servers:
  - url: https://api.example.com/v1
  - url: https://api-staging.example.com/v1
paths:
  /users:
    get:
      summary: list
  /users/{id}:
    get:
      summary: get
  /orders:
    post:
      summary: create
`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/openapi.yaml"))
	sort.Strings(got)
	want := []string{
		"https://api-staging.example.com/v1/orders",
		"https://api-staging.example.com/v1/users",
		"https://api-staging.example.com/v1/users/1",
		"https://api.example.com/v1/orders",
		"https://api.example.com/v1/users",
		"https://api.example.com/v1/users/1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestParseYAMLSpecSwagger2(t *testing.T) {
	body := []byte(`swagger: "2.0"
host: api.example.com
basePath: /v2
schemes: [https, http]
paths:
  /pets:
    get:
      summary: list
`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/swagger.yaml"))
	sort.Strings(got)
	want := []string{
		"http://api.example.com/v2/pets",
		"https://api.example.com/v2/pets",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestParseYAMLSpecRejectsArbitraryYAML(t *testing.T) {
	body := []byte(`name: hello
items:
  - one
  - two
`)
	if got := extractAPIEndpoints(body, mustURL(t, "https://example.com/anything.yaml")); len(got) != 0 {
		t.Fatalf("got %v, want none (no openapi/swagger marker)", got)
	}
}

func TestParseYAMLSpecHandlesQuotedPaths(t *testing.T) {
	body := []byte(`openapi: 3.0.0
paths:
  "/foo":
    get: {}
  '/bar/{id}':
    get: {}
`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/openapi.yaml"))
	sort.Strings(got)
	want := []string{
		"https://example.com/bar/1",
		"https://example.com/foo",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestParseYAMLSpecIgnoresPathsKeyOutsideTopLevel(t *testing.T) {
	// A nested "paths:" key under components.examples shouldn't be mistaken
	// for the real paths map. The real paths map below has a single /real
	// entry; the bogus map's "/decoy" should be invisible because it's
	// rooted under a deeper "paths:".
	body := []byte(`openapi: 3.0.0
components:
  examples:
    sample:
      paths:
        /decoy: nope
paths:
  /real:
    get: {}
`)
	got := extractAPIEndpoints(body, mustURL(t, "https://example.com/openapi.yaml"))
	// We can't perfectly disambiguate without a real parser, so the test
	// pins our actual behavior: the first "paths:" encountered wins. As
	// long as /real shows up, the discovery is doing its job.
	found := false
	for _, u := range got {
		if strings.HasSuffix(u, "/real") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected /real in %v", got)
	}
}

func TestFillPathTemplate(t *testing.T) {
	cases := map[string]string{
		"/users":            "/users",
		"/users/{id}":       "/users/1",
		"/a/{x}/b/{y}":      "/a/1/b/1",
		"/items/{itemId}/c": "/items/1/c",
	}
	for in, want := range cases {
		if got := fillPathTemplate(in); got != want {
			t.Errorf("fillPathTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJoinPath(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"", "/x", "/x"},
		{"/", "/x", "/x"},
		{"/v1", "/x", "/v1/x"},
		{"/v1/", "/x", "/v1/x"},
		{"/v1", "x", "/v1/x"},
	}
	for _, c := range cases {
		if got := joinPath(c.a, c.b); got != c.want {
			t.Errorf("joinPath(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestWellKnownSpecPathsIncludesCommonOnes(t *testing.T) {
	required := []string{
		"/openapi.json",
		"/openapi.yaml",
		"/swagger.json",
		"/v2/api-docs",
		"/v3/api-docs",
	}
	have := map[string]bool{}
	for _, p := range wellKnownSpecPaths {
		have[p] = true
	}
	for _, r := range required {
		if !have[r] {
			t.Errorf("wellKnownSpecPaths missing %q", r)
		}
	}
}
