package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/scope"
)

// OpenRedirect probes whether a target page reflects an attacker-controlled
// URL parameter into its redirect Location. For each candidate param name
// the check issues a single no-follow GET with the param set to a canary on
// a reserved (.example) domain; a 3xx response whose Location points at the
// canary host means the param is unvalidated.
//
// Candidates are the canonical redirect names (next, url, redirect, ...)
// plus any param already present on the target URL - so apps using a
// non-standard name visible in real traffic still get covered.
//
// This is an active (LevelDefault) check; it only runs when the user opts
// into a `default` or `aggressive` scan. Per-host rate limiting in the
// HTTP client governs probe pacing.
type OpenRedirect struct{}

func (OpenRedirect) Name() string { return "open-redirect" }

func (OpenRedirect) Level() Level { return LevelDefault }

const (
	// openRedirectCanary uses RFC 2606 .example so the host is guaranteed
	// unregistered. The path marker makes the probe easy to spot in target
	// access logs.
	openRedirectCanary  = "https://evil.example/hyperz-probe"
	openRedirectBodyCap = 4 << 10
)

// openRedirectParams is the set of query parameter names that historically
// carry redirect destinations across common web frameworks and login flows.
// Keep this list curated rather than exhaustive: every additional name is
// one more probe per scanned URL, and the open-set of existing params on
// the target URL already catches app-specific cases.
var openRedirectParams = []string{
	"continue",
	"dest",
	"destination",
	"goto",
	"next",
	"redir",
	"redirect",
	"redirect_uri",
	"redirect_url",
	"return",
	"returnTo",
	"returnUrl",
	"return_url",
	"target",
	"url",
}

func (c OpenRedirect) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, target string) ([]Finding, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		// Nothing actionable: an unparseable target isn't a finding, and
		// returning an error would pollute the scan summary with noise that
		// has nothing to do with the check.
		return nil, nil
	}
	// Non-passive checks must consult scope before probing. The scanner only
	// dispatches in-scope targets, but the contract says checks re-affirm
	// before sending crafted traffic.
	if !sc.Allows(u) {
		return nil, nil
	}

	var findings []Finding
	var firstErr error
	for _, name := range openRedirectCandidates(u) {
		if ctx.Err() != nil {
			break
		}
		f, err := c.probe(ctx, client, target, u, name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	// Only surface an error when we have nothing to show - the scanner
	// discards findings on error, so a single transient probe failure
	// shouldn't erase hits the other probes turned up. Wholesale failure
	// (e.g. unreachable host) still propagates because every probe errored.
	if firstErr != nil && len(findings) == 0 {
		return nil, firstErr
	}
	return findings, nil
}

// openRedirectCandidates returns the deduped, sorted set of param names to
// probe: the canonical list plus any param already present on the target
// URL. Sorted output keeps probe order (and therefore finding order) stable
// across runs.
func openRedirectCandidates(u *url.URL) []string {
	set := make(map[string]struct{}, len(openRedirectParams))
	for _, p := range openRedirectParams {
		set[p] = struct{}{}
	}
	for k := range u.Query() {
		if k == "" {
			continue
		}
		set[k] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// probe issues one no-follow GET with `param` overlaid to the canary value;
// other query params on the target URL are preserved. Returns a finding
// when the response is a 3xx whose Location echoes the canary host, or
// (nil, nil) when the param isn't reflected.
func (c OpenRedirect) probe(ctx context.Context, client *httpclient.Client, target string, u *url.URL, param string) (*Finding, error) {
	q := u.Query()
	q.Set(param, openRedirectCanary)
	probeURL := *u
	probeURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if !isRedirectStatus(resp.StatusCode) {
		return nil, nil
	}
	loc := resp.Header.Get("Location")
	if !openRedirectMatches(loc, openRedirectCanary) {
		return nil, nil
	}

	body, truncated, err := httpclient.ReadBodyCapped(resp, openRedirectBodyCap)
	if err != nil {
		return nil, err
	}
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      probeURL.String(),
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("Open redirect via ?%s=", param),
		Detail: fmt.Sprintf(
			"Parameter %q is reflected unvalidated into the Location header. "+
				"Probe %s=%s produced Location: %s — an attacker can craft a link to %s that bounces victims to any external host.",
			param, param, openRedirectCanary, loc, probeURL.String()),
		CWE:   "CWE-601",
		OWASP: "A01:2021 Broken Access Control",
		Remediation: "Validate the redirect target against an allowlist of trusted hosts (or restrict to same-origin paths). " +
			"Never use unvalidated user input as a Location value; map opaque tokens to known destinations instead.",
		Evidence: &Evidence{
			Method:     http.MethodGet,
			RequestURL: probeURL.String(),
			Status:     resp.StatusCode,
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		// Dedupe per (page, param): the same vulnerable page hit by the
		// crawler from many entry points is one issue per param. Including
		// the param name keeps distinct vulnerabilities (e.g. both `next`
		// and `redirect`) from collapsing into a single finding.
		DedupeKey: MakeDedupeKey(c.Name(), pageScope(&probeURL), "param:"+param),
	}, nil
}

// isRedirectStatus reports whether code is one of the redirect statuses that
// carry a Location header. We accept the full 3xx range that browsers act on
// (301, 302, 303, 307, 308) so the probe catches both legacy and modern
// redirect implementations. 304 (Not Modified) is excluded; it has no
// Location semantics in this context.
func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	}
	return false
}

// openRedirectMatches reports whether the Location header sends the victim
// to the canary host. We parse Location and compare hosts case-insensitively
// so that both absolute ("https://evil.example/x") and protocol-relative
// ("//evil.example/x") forms match; same-origin paths produce a non-canary
// host and are rejected.
func openRedirectMatches(location, canary string) bool {
	loc := strings.TrimSpace(location)
	if loc == "" {
		return false
	}
	cu, err := url.Parse(canary)
	if err != nil || cu.Host == "" {
		return false
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return false
	}
	return strings.EqualFold(lu.Host, cu.Host)
}

// pageScope returns scheme://host/path (no query, no fragment) for use as a
// dedupe scope. Open redirect on /foo and /bar are separate issues; the
// query string shouldn't fragment the key (the probe always rewrites it).
func pageScope(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return u.Scheme + "://" + u.Host + path
}
