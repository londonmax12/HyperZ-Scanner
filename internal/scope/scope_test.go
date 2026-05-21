package scope

import (
	"net/url"
	"reflect"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestNilScopeAllowsEverything(t *testing.T) {
	var s *Scope
	if !s.Allows(mustParse(t, "https://anywhere.example/x")) {
		t.Error("nil scope must allow URLs")
	}
	if !s.AllowsDepth(99) {
		t.Error("nil scope must allow any depth")
	}
	if s.MaxDepth() != -1 {
		t.Errorf("nil MaxDepth = %d, want -1", s.MaxDepth())
	}
	if s.Hosts() != nil {
		t.Error("nil scope Hosts() must be nil")
	}
	s.AllowHost("x.example") // must not panic
}

func TestEmptyHostsAllowsAnyHost(t *testing.T) {
	s, err := New(Config{MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Allows(mustParse(t, "https://a.example/")) {
		t.Error("empty host list should allow any host")
	}
	if !s.Allows(mustParse(t, "https://b.example/")) {
		t.Error("empty host list should allow any host")
	}
}

func TestHostFilterIsCaseInsensitive(t *testing.T) {
	s, err := New(Config{Hosts: []string{"Example.COM"}, MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Allows(mustParse(t, "https://example.com/")) {
		t.Error("expected example.com to match Example.COM")
	}
	if s.Allows(mustParse(t, "https://other.com/")) {
		t.Error("expected other.com to be rejected")
	}
}

func TestAllowHostAddsToSet(t *testing.T) {
	s, err := New(Config{MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	s.AllowHost("a.example")
	s.AllowHost("  B.Example  ")
	s.AllowHost("")
	got := s.Hosts()
	want := []string{"a.example", "b.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts() = %v, want %v", got, want)
	}
}

func TestPortRange(t *testing.T) {
	s, err := New(Config{Ports: "8000-8999", MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"http://h.example:8080/":  true,
		"http://h.example:8999/":  true,
		"http://h.example:9000/":  false,
		"http://h.example/":       false, // defaults to 80
		"https://h.example/":      false, // defaults to 443
		"https://h.example:8443/": true,
	}
	for raw, want := range cases {
		if got := s.Allows(mustParse(t, raw)); got != want {
			t.Errorf("Allows(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestSinglePort(t *testing.T) {
	s, err := New(Config{Ports: "443", MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Allows(mustParse(t, "https://x/")) {
		t.Error("https default port 443 should match Ports=443")
	}
	if s.Allows(mustParse(t, "https://x:8443/")) {
		t.Error("8443 should be out of range when Ports=443")
	}
}

func TestPortParseErrors(t *testing.T) {
	bad := []string{"abc", "0", "65536", "100-50", "100-abc", "-5"}
	for _, p := range bad {
		if _, err := New(Config{Ports: p}); err == nil {
			t.Errorf("Ports=%q: expected error", p)
		}
	}
}

func TestPathExcludeWinsOverInclude(t *testing.T) {
	s, err := New(Config{
		PathInclude: []string{`^/api/`},
		PathExclude: []string{`/api/internal/`},
		MaxDepth:    -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://h/api/users":         true,
		"https://h/api/internal/keys": false, // excluded
		"https://h/static/app.js":     false, // not in include
		"https://h/":                  false, // not in include
	}
	for raw, want := range cases {
		if got := s.Allows(mustParse(t, raw)); got != want {
			t.Errorf("Allows(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestPathOnlyExclude(t *testing.T) {
	s, err := New(Config{PathExclude: []string{`^/logout`}, MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	if s.Allows(mustParse(t, "https://h/logout")) {
		t.Error("/logout should be excluded")
	}
	if !s.Allows(mustParse(t, "https://h/home")) {
		t.Error("/home should pass when only exclude is set")
	}
}

func TestPathRegexCompileError(t *testing.T) {
	if _, err := New(Config{PathInclude: []string{"["}}); err == nil {
		t.Error("expected compile error on bad PathInclude regex")
	}
	if _, err := New(Config{PathExclude: []string{"("}}); err == nil {
		t.Error("expected compile error on bad PathExclude regex")
	}
}

func TestAllowsDepth(t *testing.T) {
	s, err := New(Config{MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[int]bool{0: true, 2: true, 3: false}
	for d, want := range cases {
		if got := s.AllowsDepth(d); got != want {
			t.Errorf("AllowsDepth(%d) = %v, want %v", d, got, want)
		}
	}
}

func TestMaxDepthNegativeIsUnlimited(t *testing.T) {
	s, err := New(Config{MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !s.AllowsDepth(1000) {
		t.Error("MaxDepth=-1 should allow any depth")
	}
}

func TestAllowsRejectsURLOutOfHost(t *testing.T) {
	s, err := New(Config{Hosts: []string{"a.example"}, MaxDepth: -1})
	if err != nil {
		t.Fatal(err)
	}
	if s.Allows(mustParse(t, "https://b.example/")) {
		t.Error("b.example should be out of scope")
	}
	if !s.Allows(mustParse(t, "https://a.example/anything")) {
		t.Error("a.example should be in scope")
	}
}
