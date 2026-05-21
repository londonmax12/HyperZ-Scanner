package crawler

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseRobotsCollectsStarGroup(t *testing.T) {
	body := `
User-agent: googlebot
Disallow: /private-google

User-agent: *
Disallow: /a
Disallow: /b
Allow: /a/public
# comment
  Sitemap:   https://example.com/sitemap.xml

User-agent: bingbot
Disallow: /private-bing

Sitemap: https://example.com/sitemap2.xml
`
	r := parseRobots(strings.NewReader(body))
	sort.Strings(r.disallow)
	sort.Strings(r.allow)
	sort.Strings(r.sitemaps)

	if !reflect.DeepEqual(r.disallow, []string{"/a", "/b"}) {
		t.Errorf("disallow = %v", r.disallow)
	}
	if !reflect.DeepEqual(r.allow, []string{"/a/public"}) {
		t.Errorf("allow = %v", r.allow)
	}
	wantSM := []string{"https://example.com/sitemap.xml", "https://example.com/sitemap2.xml"}
	if !reflect.DeepEqual(r.sitemaps, wantSM) {
		t.Errorf("sitemaps = %v, want %v", r.sitemaps, wantSM)
	}
}

func TestParseRobotsIgnoresCommentsAndBlankLines(t *testing.T) {
	body := `
# top comment

User-agent: *
# nested comment
Disallow: /x # trailing
`
	r := parseRobots(strings.NewReader(body))
	if !reflect.DeepEqual(r.disallow, []string{"/x"}) {
		t.Fatalf("disallow = %v, want [/x]", r.disallow)
	}
}

func TestRobotsBlocked(t *testing.T) {
	r := robotsRules{
		disallow: []string{"/a", "/a/private"},
		allow:    []string{"/a/private/ok"},
	}
	cases := []struct {
		path    string
		blocked bool
	}{
		{"/", false},                    // no match
		{"/b", false},                   // no disallow
		{"/a", true},                    // matches /a
		{"/a/foo", true},                // matches /a (longest)
		{"/a/private/x", true},          // longest disallow
		{"/a/private/ok/file", false},   // equal-length allow beats disallow at same prefix
		{"/a/private", true},            // no allow that long
	}
	for _, c := range cases {
		if got := r.blocked(c.path); got != c.blocked {
			t.Errorf("blocked(%q) = %v, want %v", c.path, got, c.blocked)
		}
	}
}

func TestRobotsBlockedAllowEqualsDisallow(t *testing.T) {
	// Per spec: equal-length Allow beats Disallow.
	r := robotsRules{
		disallow: []string{"/p"},
		allow:    []string{"/p"},
	}
	if r.blocked("/p/x") {
		t.Fatal("equal-length allow should win over disallow")
	}
}

func TestRobotsBlockedNoDisallow(t *testing.T) {
	r := robotsRules{}
	if r.blocked("/anything") {
		t.Fatal("empty rules should never block")
	}
}
