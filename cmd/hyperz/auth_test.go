package main

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestParseBasicAuth(t *testing.T) {
	cases := []struct {
		in         string
		wantUser   string
		wantPass   string
		wantNil    bool
		wantErr    bool
	}{
		{"", "", "", true, false},
		{"alice:secret", "alice", "secret", false, false},
		{"alice:", "alice", "", false, false},
		{":pass-only", "", "pass-only", false, false},
		{"alice:pa:ss", "alice", "pa:ss", false, false}, // colons survive in password
		{"no-colon", "", "", false, true},
	}
	for _, tc := range cases {
		got, err := parseBasicAuth(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseBasicAuth(%q) err = %v, wantErr=%v", tc.in, err, tc.wantErr)
		}
		if tc.wantErr {
			continue
		}
		if tc.wantNil {
			if got != nil {
				t.Fatalf("parseBasicAuth(%q) = %+v, want nil", tc.in, got)
			}
			continue
		}
		if got == nil || got.Username != tc.wantUser || got.Password != tc.wantPass {
			t.Fatalf("parseBasicAuth(%q) = %+v, want user=%q pass=%q",
				tc.in, got, tc.wantUser, tc.wantPass)
		}
	}
}

func TestParseExtraHeaders(t *testing.T) {
	h, err := parseExtraHeaders([]string{
		"X-API-Key: k1",
		"  X-Trace : trace-1 ",
		"",
	})
	if err != nil {
		t.Fatalf("parseExtraHeaders: %v", err)
	}
	if got := h.Get("X-Api-Key"); got != "k1" {
		t.Errorf("X-API-Key = %q", got)
	}
	if got := h.Get("X-Trace"); got != "trace-1" {
		t.Errorf("X-Trace = %q", got)
	}

	if _, err := parseExtraHeaders([]string{"no-colon"}); err == nil {
		t.Error("expected error for header without colon")
	}
	if _, err := parseExtraHeaders([]string{": empty-name"}); err == nil {
		t.Error("expected error for empty header name")
	}
}

func TestParseCookieSpecs(t *testing.T) {
	cookies, err := parseCookieSpecs([]string{
		"sid=abc",
		"theme=dark; lang=en",
		"",
	})
	if err != nil {
		t.Fatalf("parseCookieSpecs: %v", err)
	}
	want := map[string]string{"sid": "abc", "theme": "dark", "lang": "en"}
	if len(cookies) != len(want) {
		t.Fatalf("got %d cookies, want %d (%v)", len(cookies), len(want), cookies)
	}
	for _, c := range cookies {
		if want[c.Name] != c.Value {
			t.Errorf("cookie %q = %q, want %q", c.Name, c.Value, want[c.Name])
		}
	}

	if _, err := parseCookieSpecs([]string{"bad"}); err == nil {
		t.Error("expected error for cookie without '='")
	}
}

func TestNewCookieJarSeedsUnscoped(t *testing.T) {
	cs, err := parseCookieSpecs([]string{"sid=abc"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	jar, err := newCookieJar([]string{"https://example.com/path"}, nil, cs)
	if err != nil {
		t.Fatalf("newCookieJar: %v", err)
	}
	u, _ := url.Parse("https://example.com/anywhere")
	got := jar.Cookies(u)
	if len(got) != 1 || got[0].Name != "sid" || got[0].Value != "abc" {
		t.Fatalf("jar.Cookies = %+v, want sid=abc", got)
	}

	// Cookie must not leak to unrelated hosts.
	other, _ := url.Parse("https://other.test/")
	if cookies := jar.Cookies(other); len(cookies) != 0 {
		t.Fatalf("cookies leaked to other host: %+v", cookies)
	}
}

func TestLoadCookiesFileNetscape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cookies.txt")
	body := "# Netscape HTTP Cookie File\n" +
		"# This is a comment\n" +
		"example.com\tFALSE\t/\tFALSE\t0\tsid\tabc\n" +
		"#HttpOnly_secure.test\tFALSE\t/\tTRUE\t0\ttoken\txyz\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	scoped, unscoped, err := loadCookiesFile(path)
	if err != nil {
		t.Fatalf("loadCookiesFile: %v", err)
	}
	if len(unscoped) != 0 {
		t.Fatalf("got %d unscoped cookies, want 0", len(unscoped))
	}
	if len(scoped) != 2 {
		t.Fatalf("got %d scoped cookies, want 2", len(scoped))
	}

	jar, err := newCookieJar(nil, scoped, nil)
	if err != nil {
		t.Fatalf("newCookieJar: %v", err)
	}
	u, _ := url.Parse("http://example.com/")
	if got := jar.Cookies(u); len(got) != 1 || got[0].Name != "sid" {
		t.Fatalf("example.com cookies = %+v, want [sid=abc]", got)
	}
	su, _ := url.Parse("https://secure.test/")
	if got := jar.Cookies(su); len(got) != 1 || got[0].Name != "token" {
		t.Fatalf("secure.test cookies = %+v, want [token=xyz]", got)
	}
}

func TestLoadCookiesFilePlain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cookies.txt")
	body := "# plain format\n" +
		"sid=abc\n" +
		"example.com theme=dark\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	scoped, unscoped, err := loadCookiesFile(path)
	if err != nil {
		t.Fatalf("loadCookiesFile: %v", err)
	}
	if len(scoped) != 1 || scoped[0].Domain != "example.com" || scoped[0].Name != "theme" {
		t.Fatalf("scoped = %+v, want [example.com theme=dark]", scoped)
	}
	if len(unscoped) != 1 || unscoped[0].Name != "sid" || unscoped[0].Value != "abc" {
		t.Fatalf("unscoped = %+v, want [sid=abc]", unscoped)
	}
}
