package checks

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

type CookieAttributes struct{}

func (CookieAttributes) Name() string { return "cookie-attributes" }

func (CookieAttributes) Level() Level { return LevelPassive }

// attrRule describes one cookie-attribute finding's metadata. Severity is
// fixed per attribute; the dynamic parts (cookie name, URL) fill the title
// and detail at emit time.
type attrRule struct {
	severity    Severity
	cwe         string
	owasp       string
	remediation string
}

// All three attributes share OWASP A05:2021. CWEs differ: CWE-614 is the
// canonical "missing Secure", CWE-1004 the canonical "missing HttpOnly",
// CWE-1275 covers improper SameSite (including absence, which browsers now
// treat as Lax; still worth flagging because explicit beats implicit).
var cookieAttrRules = map[string]attrRule{
	"Secure": {
		severity:    SeverityMedium,
		cwe:         "CWE-614",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Add the Secure attribute so the cookie is only sent over HTTPS. SameSite=None additionally requires Secure to be set.",
	},
	"HttpOnly": {
		severity:    SeverityLow,
		cwe:         "CWE-1004",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Add HttpOnly so the cookie is not accessible via document.cookie, reducing the impact of XSS-driven session theft.",
	},
	"SameSite": {
		severity:    SeverityLow,
		cwe:         "CWE-1275",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Set SameSite=Lax (or Strict for session cookies). Use SameSite=None; Secure only for cross-site contexts.",
	},
}

func (c CookieAttributes) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, 0)
	if err != nil {
		return nil, err
	}

	isHTTPS := strings.HasPrefix(strings.ToLower(p.URL), "https://")
	hostScope := HostScope(p.URL)
	evidence := BuildEvidence("GET", p.URL, snap.Status, snap.Headers, "")

	// http.Response.Cookies parses Set-Cookie headers; build a synthetic
	// Response so we get the same parsing whether snap came from a live
	// fetch or from the crawler's Page.
	cookies := (&http.Response{Header: snap.Headers}).Cookies()
	sort.SliceStable(cookies, func(i, j int) bool { return cookies[i].Name < cookies[j].Name })

	var findings []Finding
	for _, ck := range cookies {
		// Secure is only enforceable / meaningful over HTTPS; a Set-Cookie
		// arriving on http:// can't be "fixed" by adding Secure without also
		// moving the host to HTTPS, so we skip the flag on plaintext to
		// avoid noise. The Secure-requires-HTTPS guidance shows up via the
		// HSTS missing-header check instead.
		if !ck.Secure && isHTTPS {
			findings = append(findings, c.finding(p.URL, hostScope, ck.Name, "Secure", evidence))
		}
		if !ck.HttpOnly {
			findings = append(findings, c.finding(p.URL, hostScope, ck.Name, "HttpOnly", evidence))
		}
		// Flag anything that isn't an explicit Lax/Strict/None. Two cases
		// both fall here: the SameSite attribute was absent (parser leaves
		// the field at the zero value) and the attribute was present but
		// equal to http.SameSiteDefaultMode. Both pick the browser's
		// implicit behavior instead of declaring an intent; exactly what
		// we want to surface.
		if ck.SameSite != http.SameSiteLaxMode &&
			ck.SameSite != http.SameSiteStrictMode &&
			ck.SameSite != http.SameSiteNoneMode {
			findings = append(findings, c.finding(p.URL, hostScope, ck.Name, "SameSite", evidence))
		}
	}
	return findings, nil
}

func (c CookieAttributes) finding(targetURL, hostScope, cookieName, attr string, ev *Evidence) Finding {
	rule := cookieAttrRules[attr]
	return Finding{
		Check:       c.Name(),
		Target:      targetURL,
		URL:         targetURL,
		Severity:    rule.severity,
		Title:       fmt.Sprintf("cookie %q missing %s attribute", cookieName, attr),
		Detail:      fmt.Sprintf("Set-Cookie for %q at %s did not include %s", cookieName, targetURL, attr),
		CWE:         rule.cwe,
		OWASP:       rule.owasp,
		Remediation: rule.remediation,
		Evidence:    ev,
		// Per-host + cookie name + attribute: the same cookie missing the
		// same flag on every crawled page is one issue, not N. Different
		// cookies or different attributes get distinct keys.
		DedupeKey: MakeDedupeKey(c.Name(), hostScope, "cookie:"+cookieName, "attr:"+attr),
	}
}
