package checks

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strings"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

type SecurityHeaders struct{}

func (SecurityHeaders) Name() string { return "security-headers" }

func (SecurityHeaders) Level() Level { return LevelPassive }

// headerRule describes one missing-header finding's metadata. We keep CWE/
// OWASP/remediation alongside severity so the check stays the single source
// of truth; reporters just render what's set on the Finding.
type headerRule struct {
	severity    Severity
	cwe         string
	owasp       string
	remediation string
}

// All five rules map to OWASP A05:2021 Security Misconfiguration. CWE-693
// (Protection Mechanism Failure) covers the general "expected control is
// absent" pattern; CWE-1021 specifically covers clickjacking (X-Frame-
// Options / frame-ancestors).
var headerRules = map[string]headerRule{
	"Content-Security-Policy": {
		severity:    SeverityMedium,
		cwe:         "CWE-693",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Set Content-Security-Policy with a restrictive default-src and explicit allowlists for script-src, style-src, and frame-ancestors. Start in Report-Only mode if needed.",
	},
	"Strict-Transport-Security": {
		severity:    SeverityMedium,
		cwe:         "CWE-319",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload over HTTPS. Confirm all subdomains serve HTTPS before enabling includeSubDomains.",
	},
	"X-Content-Type-Options": {
		severity:    SeverityLow,
		cwe:         "CWE-693",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
	},
	"X-Frame-Options": {
		severity:    SeverityLow,
		cwe:         "CWE-1021",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Set X-Frame-Options: DENY (or SAMEORIGIN) and/or Content-Security-Policy: frame-ancestors 'none' to mitigate clickjacking.",
	},
	"Referrer-Policy": {
		severity:    SeverityLow,
		cwe:         "CWE-200",
		owasp:       "A05:2021 Security Misconfiguration",
		remediation: "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for higher-sensitivity properties).",
	},
}

// isHTMLContentType reports whether ct names an HTML document. Parameters
// such as `; charset=utf-8` are stripped before comparison so a perfectly
// labeled response is not skipped on a technicality. A missing or
// unparseable Content-Type returns false: a server that does not declare
// its body's type is not the audience for browser-rendering headers.
func isHTMLContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "text/html" || mediaType == "application/xhtml+xml"
}

// severityRank orders severities so the consolidated finding can adopt the
// worst severity among all missing headers. Higher number = worse.
var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

func (c SecurityHeaders) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, 0)
	if err != nil {
		return nil, err
	}
	// CSP, X-Frame-Options, and Referrer-Policy govern HTML rendering in a
	// browser; flagging them missing on a JSON API, an image, or a 404 page
	// is noise. Restrict the check to 200 OK responses the server itself
	// labeled as HTML so the findings track real attack surface.
	if snap.Status != http.StatusOK || !isHTMLContentType(snap.Headers.Get("Content-Type")) {
		return nil, nil
	}

	// Iterate in sorted header order so the missing-set, CWE list, and
	// remediation text are stable across runs.
	names := make([]string, 0, len(headerRules))
	for h := range headerRules {
		names = append(names, h)
	}
	sort.Strings(names)

	var missing []string
	for _, header := range names {
		if snap.Headers.Get(header) == "" {
			missing = append(missing, header)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}

	// Consolidate every missing header into a single finding. Five missing
	// headers on the same page is one configuration defect with five facets,
	// not five independent issues; emitting five rows just inflates the
	// report and forces the reader to mentally re-join them.
	maxSev := SeverityInfo
	seenCWE := map[string]bool{}
	var cwes, remediations []string
	for _, h := range missing {
		r := headerRules[h]
		if severityRank[r.severity] > severityRank[maxSev] {
			maxSev = r.severity
		}
		if !seenCWE[r.cwe] {
			seenCWE[r.cwe] = true
			cwes = append(cwes, r.cwe)
		}
		remediations = append(remediations, h+": "+r.remediation)
	}

	var title string
	if len(missing) == 1 {
		title = "missing security header: " + missing[0]
	} else {
		title = fmt.Sprintf("missing %d security headers", len(missing))
	}

	return []Finding{{
		Check:    c.Name(),
		Target:   p.URL,
		URL:      p.URL,
		Severity: maxSev,
		Title:    title,
		Detail:   fmt.Sprintf("response from %s did not include: %s", p.URL, strings.Join(missing, ", ")),
		CWE:      strings.Join(cwes, ", "),
		// All header rules map to OWASP A05:2021 Security Misconfiguration,
		// so consolidating doesn't lose information here.
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: strings.Join(remediations, " "),
		Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
		// Per-host: missing headers on example.com is one site-wide config
		// issue, not one per crawled page. No per-header suffix now that
		// every missing header is folded into a single finding.
		DedupeKey: MakeKey(c.Name(), ScopeHost, p.URL, "missing-headers"),
	}}, nil
}
