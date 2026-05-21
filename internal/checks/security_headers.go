package checks

import (
	"context"
	"fmt"
	"sort"

	"github.com/londonball/hyperz/internal/httpclient"
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

func (c SecurityHeaders) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, target string) ([]Finding, error) {
	resp, err := client.Get(ctx, target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// resp.Request reflects the final request after redirects, so URL and
	// evidence match what was actually observed.
	finalURL := target
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	scope := HostScope(finalURL)
	evidence := BuildEvidence("GET", finalURL, resp.StatusCode, resp.Header, "")

	// Iterate in sorted header order so the output is stable across runs.
	names := make([]string, 0, len(headerRules))
	for h := range headerRules {
		names = append(names, h)
	}
	sort.Strings(names)

	var findings []Finding
	for _, header := range names {
		if resp.Header.Get(header) != "" {
			continue
		}
		rule := headerRules[header]
		findings = append(findings, Finding{
			Check:       c.Name(),
			Target:      target,
			URL:         finalURL,
			Severity:    rule.severity,
			Title:       "missing security header: " + header,
			Detail:      fmt.Sprintf("response from %s did not include %s", finalURL, header),
			CWE:         rule.cwe,
			OWASP:       rule.owasp,
			Remediation: rule.remediation,
			Evidence:    evidence,
			// Per-host: missing CSP on example.com is one issue, not one per
			// crawled page. Including the header name prevents collisions
			// between rules at the same scope.
			DedupeKey: MakeDedupeKey(c.Name(), scope, "missing-header:"+header),
		})
	}
	return findings, nil
}
