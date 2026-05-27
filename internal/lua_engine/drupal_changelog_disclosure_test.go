package lua_engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// TestDrupalChangelogFiresOnDrupal7Body confirms the check parses the
// leading "Drupal x.y.z, date" line out of CHANGELOG.txt and emits a
// finding whose title carries the disclosed version.
func TestDrupalChangelogFiresOnDrupal7Body(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/CHANGELOG.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Drupal 7.94, 2023-08-16\n----------------------\n- Bugfix: blah blah blah.\n"))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "drupal_changelog_disclosure.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "drupal"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1; got %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityLow {
		t.Errorf("severity = %q, want low", f.Severity)
	}
	if !strings.Contains(f.Title, "7.94") {
		t.Errorf("title should carry the disclosed version 7.94; got %q", f.Title)
	}
}

// TestDrupalChangelogIgnoresNonDrupalBody covers a 200-page response
// whose body is text/plain but does not lead with the "Drupal x.y.z"
// token. A naive substring-anywhere match would false-positive on
// marketing copy that mentions Drupal; the anchored match rejects it.
func TestDrupalChangelogIgnoresNonDrupalBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("This site is powered by Drupal 7 and other technologies.\n"))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "drupal_changelog_disclosure.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "drupal"})

	findings, err := c.Run(ctx, client, nil, page.Page{URL: srv.URL + "/"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0 (marketing copy must not false-positive); got %+v", len(findings), findings)
	}
}

// TestDrupalChangelogGateOnNonDrupalHost asserts AppliesTo gates the
// check to detected Drupal hosts. A WordPress host's stack should be
// rejected by the gate so the scanner skips dispatch entirely.
func TestDrupalChangelogGateOnNonDrupalHost(t *testing.T) {
	c := loadCatalogCheck(t, "drupal_changelog_disclosure.lua")

	if !c.AppliesTo(&fingerprint.Stack{CMS: "drupal"}) {
		t.Errorf("Drupal host must match the gate")
	}
	if c.AppliesTo(&fingerprint.Stack{CMS: "wordpress"}) {
		t.Errorf("WordPress host must NOT match the Drupal gate")
	}
	if !c.AppliesTo(nil) {
		t.Errorf("nil stack (no fingerprint) must be permissive")
	}
}

// TestDrupalChangelogOncePerHost confirms claim_once short-circuits
// later same-host pages, so a 50-page crawl of a Drupal site issues
// exactly one /CHANGELOG.txt request.
func TestDrupalChangelogOncePerHost(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/CHANGELOG.txt" {
			http.NotFound(w, r)
			return
		}
		hits++
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Drupal 7.10, 2013-12-18\n"))
	}))
	defer srv.Close()

	c := loadCatalogCheck(t, "drupal_changelog_disclosure.lua")
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test"})
	ctx := WithStack(context.Background(), &fingerprint.Stack{CMS: "drupal"})

	for i := 0; i < 3; i++ {
		p := page.Page{URL: srv.URL + "/page" + string(rune('0'+i))}
		if _, err := c.Run(ctx, client, nil, p); err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
	}
	if hits != 1 {
		t.Errorf("upstream hits = %d, want 1 (claim_once must short-circuit later pages)", hits)
	}
}
