package lua_engine

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// loadCatalogCheck reads filename from the embedded check catalog and
// returns the loaded LuaCheck. Useful for end-to-end tests that want
// to exercise a real ship-with-the-binary check rather than a hand-
// rolled inline module.
func loadCatalogCheck(t *testing.T, filename string) *LuaCheck {
	t.Helper()
	src, err := fs.ReadFile(checks.Sources, filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	c, err := Load(filename, src)
	if err != nil {
		t.Fatalf("Load %s: %v", filename, err)
	}
	return c
}

// TestWPRestUserEnumFiresOnExposedEndpoint exercises the WP REST API
// user-enumeration check against an httptest server that mimics the
// /wp-json/wp/v2/users response shape. The gate (applies_to = cms:
// wordpress) is satisfied via WithStack so the scanner's StackGated
// filter would let this check run; here we call Run directly to keep
// the test focused on the .lua detection logic.
func TestWPRestUserEnumFiresOnExposedEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wp-json/wp/v2/users" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"id": 1, "name": "Admin", "slug": "admin"},
			{"id": 2, "name": "Author One", "slug": "author1"}
		]`))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_rest_user_enum.lua")

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	stack := &fingerprint.Stack{CMS: "wordpress"}
	ctx := WithStack(context.Background(), stack)

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (no patched_in so no inference); got %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if !strings.Contains(f.Title, "WordPress REST API") {
		t.Errorf("title = %q, want the WordPress REST API phrasing", f.Title)
	}
	if !strings.Contains(f.Detail, "admin") || !strings.Contains(f.Detail, "author1") {
		t.Errorf("detail should name the disclosed slugs; got %q", f.Detail)
	}
	if u, err := url.Parse(f.URL); err != nil || u.Path != "/wp-json/wp/v2/users" {
		t.Errorf("finding URL = %q, want a /wp-json/wp/v2/users URL", f.URL)
	}
}

// TestWPRestUserEnumIgnoresNonJSONResponse confirms the check skips
// hosts whose /wp-json/wp/v2/users path returns HTML / 404 / etc. -
// the failure mode would be a false positive on misconfigured hosts
// that serve an HTML index page for unknown REST routes.
func TestWPRestUserEnumIgnoresNonJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html>not a REST endpoint</html>`))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_rest_user_enum.lua")

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 (HTML response is not a user array); got %+v", len(findings), findings)
	}
}

// TestWPRestUserEnumIgnoresEmptyArray covers the case where the
// endpoint returns 200 + an empty JSON array - the host has the
// route registered but no users with published posts. Not a finding.
func TestWPRestUserEnumIgnoresEmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_rest_user_enum.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 (empty array)", len(findings))
	}
}

// TestWPRestUserEnumGateOnNonWordPressHost confirms the AppliesTo
// hook returns false when the detected stack is not WordPress. The
// scanner's StackGated filter would skip dispatch in that case; this
// test asserts the gate itself, since Run does not re-check (the
// scanner is the authority on dispatch).
func TestWPRestUserEnumGateOnNonWordPressHost(t *testing.T) {
	c := loadCatalogCheck(t, "wp_rest_user_enum.lua")

	if !c.AppliesTo(&fingerprint.Stack{CMS: "wordpress"}) {
		t.Errorf("WordPress host must match the gate")
	}
	if c.AppliesTo(&fingerprint.Stack{CMS: "drupal"}) {
		t.Errorf("Drupal host must NOT match the gate")
	}
	if !c.AppliesTo(nil) {
		t.Errorf("nil stack (no fingerprint) must be permissive")
	}
}

// TestWPRestUserEnumOncePerHost confirms the host-claim helper
// short-circuits subsequent Run calls for the same host. Without the
// claim a 50-page crawl would issue 50 GETs to /wp-json/wp/v2/users.
func TestWPRestUserEnumOncePerHost(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wp-json/wp/v2/users" {
			http.NotFound(w, r)
			return
		}
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":1,"slug":"admin","name":"A"}]`))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "wp_rest_user_enum.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "wordpress"})

	for i := 0; i < 3; i++ {
		page := page.Page{URL: srv.URL + "/page" + string(rune('0'+i))}
		if _, err := c.Run(ctx, client, nil, page); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
	}
	if hits != 1 {
		t.Errorf("upstream hits = %d, want 1 (claim_once must short-circuit later pages)", hits)
	}
}
