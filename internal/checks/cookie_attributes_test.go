package checks

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// httpsTestClient skips cert verification so httptest.NewTLSServer's
// self-signed cert doesn't trip the check before it ever sees the cookies.
func httpsTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	return httpclient.New(httpclient.Config{
		Timeout:   5 * time.Second,
		UserAgent: "test",
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	})
}

func TestCookieAttributesName(t *testing.T) {
	if got := (CookieAttributes{}).Name(); got != "cookie-attributes" {
		t.Fatalf("Name = %q, want cookie-attributes", got)
	}
}

func TestCookieAttributesLevel(t *testing.T) {
	if got := (CookieAttributes{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestCookieAttributesNoCookiesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CookieAttributes{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestCookieAttributesFullyHardenedHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: "session", Value: "x",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CookieAttributes{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestCookieAttributesAllMissingOnHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Secure, no HttpOnly, no SameSite: expect three findings.
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CookieAttributes{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}
	gotAttrs := make([]string, 0, 3)
	for _, f := range findings {
		if f.Check != "cookie-attributes" {
			t.Errorf("unexpected check %q", f.Check)
		}
		if !strings.Contains(f.Title, `"sid"`) {
			t.Errorf("title %q should reference cookie name", f.Title)
		}
		for _, a := range []string{"Secure", "HttpOnly", "SameSite"} {
			if strings.Contains(f.Title, " missing "+a+" ") {
				gotAttrs = append(gotAttrs, a)
			}
		}
	}
	sort.Strings(gotAttrs)
	want := []string{"HttpOnly", "SameSite", "Secure"}
	for i, a := range want {
		if i >= len(gotAttrs) || gotAttrs[i] != a {
			t.Fatalf("attrs = %v, want %v", gotAttrs, want)
		}
	}
}

func TestCookieAttributesHTTPSkipsSecure(t *testing.T) {
	// On plaintext HTTP we suppress the Secure finding to keep the check
	// from screaming about something that the host can't satisfy without
	// switching to HTTPS first. HttpOnly and SameSite still fire.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CookieAttributes{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "Secure") {
			t.Errorf("did not expect Secure finding on HTTP; got %q", f.Title)
		}
	}
}

func TestCookieAttributesSeverityMapping(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CookieAttributes{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		switch {
		case strings.Contains(f.Title, "Secure"):
			if f.Severity != SeverityMedium {
				t.Errorf("Secure severity = %q, want medium", f.Severity)
			}
			if f.CWE != "CWE-614" {
				t.Errorf("Secure CWE = %q, want CWE-614", f.CWE)
			}
		case strings.Contains(f.Title, "HttpOnly"):
			if f.Severity != SeverityLow {
				t.Errorf("HttpOnly severity = %q, want low", f.Severity)
			}
			if f.CWE != "CWE-1004" {
				t.Errorf("HttpOnly CWE = %q, want CWE-1004", f.CWE)
			}
		case strings.Contains(f.Title, "SameSite"):
			if f.Severity != SeverityLow {
				t.Errorf("SameSite severity = %q, want low", f.Severity)
			}
			if f.CWE != "CWE-1275" {
				t.Errorf("SameSite CWE = %q, want CWE-1275", f.CWE)
			}
		}
	}
}

func TestCookieAttributesPopulatesEnrichedFields(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One cookie missing only HttpOnly so the finding count is 1.
		http.SetCookie(w, &http.Cookie{
			Name: "sid", Value: "abc",
			Secure: true, SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := CookieAttributes{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Target != srv.URL {
		t.Errorf("Target = %q, want %q", f.Target, srv.URL)
	}
	if f.URL == "" {
		t.Errorf("URL empty - should be the observed request URL")
	}
	if f.OWASP == "" {
		t.Errorf("OWASP empty")
	}
	if f.Remediation == "" {
		t.Errorf("Remediation empty")
	}
	if f.DedupeKey == "" {
		t.Errorf("DedupeKey empty")
	}
	if f.Evidence == nil {
		t.Fatalf("Evidence is nil")
	}
	if f.Evidence.Method != "GET" || f.Evidence.Status != 200 {
		t.Errorf("Evidence method/status = %q/%d", f.Evidence.Method, f.Evidence.Status)
	}
}

func TestCookieAttributesDedupePerCookieAndAttribute(t *testing.T) {
	// Two cookies, both bare. Two runs against the same host must yield
	// stable keys, and (cookie, attribute) pairs must each have a unique key.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "a"})
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "b"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	run := func() []Finding {
		fs, err := CookieAttributes{}.Run(context.Background(), httpsTestClient(t), nil, page.FromURL(srv.URL))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return fs
	}
	a, b := run(), run()
	if len(a) != 6 || len(b) != 6 {
		t.Fatalf("expected 6 findings each (2 cookies x 3 attrs), got %d / %d", len(a), len(b))
	}
	keyOf := func(fs []Finding) map[string]string {
		m := make(map[string]string, len(fs))
		for _, f := range fs {
			m[f.Title] = f.DedupeKey
		}
		return m
	}
	ka, kb := keyOf(a), keyOf(b)
	for title, key := range ka {
		if kb[title] != key {
			t.Errorf("dedupe key for %q drifted: %q vs %q", title, key, kb[title])
		}
	}
	seen := map[string]string{}
	for title, key := range ka {
		if other, dup := seen[key]; dup {
			t.Errorf("%q and %q share dedupe key %q", other, title, key)
		}
		seen[key] = title
	}
}

func TestCookieAttributesReturnsErrorOnNetworkFailure(t *testing.T) {
	c := httpclient.New(httpclient.Config{
		Timeout:   1 * time.Second,
		UserAgent: "test",
	})
	_, err := CookieAttributes{}.Run(context.Background(), c, nil, page.FromURL("http://hyperz-test-no-such-host.invalid"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
}
