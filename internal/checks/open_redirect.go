package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// OpenRedirect probes whether a target page reflects an attacker-controlled
// URL parameter into its redirect Location. For each candidate Sink the
// check issues a single no-follow request with the param set to a canary
// on a reserved (.example) domain; a 3xx response whose Location points at
// the canary host means the param is unvalidated.
//
// Beyond the classic Location-header path the probe also scans the response
// body for soft-redirect sinks: JavaScript navigation APIs (location.assign,
// location.href, location.replace, window.location = ...) and meta-refresh
// tags. Many SPA login pages bounce that way while returning 200, so a
// Location-only check would miss them.
//
// Candidates are chosen to keep blast radius bounded on large crawls:
//   - sinks already present on the target URL or its forms are always
//     probed (high signal; the app is already passing them, so they're
//     worth testing).
//   - the canonical redirect names (next, url, redirect, ...) only fire
//     on URLs whose path looks redirect-related (login/logout/auth/sso/
//     redirect), OR on any URL when running at LevelAggressive.
//
// Without this gating, a 200-page crawl would fan out len(openRedirectParams)
// probes per page regardless of whether the page accepts redirect params.
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
	openRedirectCanary = "https://evil.example/hyperz-probe"
	// openRedirectBodyCap bounds the response body the check reads for
	// evidence AND for body-driven sink scanning (JS navigation, meta
	// refresh). 32 KiB is large enough to cover the <head> + early <body>
	// where soft-redirect scripts typically live, without exposing the
	// check to a runaway response on a page that doesn't have one.
	openRedirectBodyCap = 32 << 10
)

// openRedirectCanaryHost caches the host portion of openRedirectCanary so
// per-probe body scans don't reparse the constant.
var openRedirectCanaryHost = func() string {
	u, err := url.Parse(openRedirectCanary)
	if err != nil || u == nil {
		return ""
	}
	return u.Host
}()

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

func (c OpenRedirect) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	target := p.URL
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

	sweep := LevelFrom(ctx) >= LevelAggressive || looksRedirectish(u.Path)
	candidates := openRedirectSinks(p, u, sweep)

	var findings []Finding
	var firstErr error
	for _, sink := range candidates {
		if ctx.Err() != nil {
			break
		}
		// Sub-scope check: a Sink discovered on a form whose action is
		// off-host (or off-scope) must not be probed even though the Run
		// scope check above passed for p.URL. Skip silently rather than
		// erroring - off-scope sinks aren't probe failures.
		if u2, err := url.Parse(sink.URL); err == nil && !sc.Allows(u2) {
			continue
		}
		f, err := c.probe(ctx, client, target, sink)
		if err != nil {
			// Every per-probe failure is breadcrumbed through the scanner's
			// error handler so a flaky host doesn't go silent when only a
			// subset of probes succeed. firstErr is retained for the
			// wholesale-failure return path below.
			Report(ctx, fmt.Errorf("probe param %q: %w", sink.Name, err))
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

// openRedirectSinks returns the deduped, sorted set of Sinks to probe.
//
// The base sink list comes from SinksFor(p), which surfaces every query
// param on the page URL plus every named input on every form. When sweep
// is true the canonical openRedirectParams list is folded in as
// synthetic LocQuery sinks on the page URL itself - gated this way to
// avoid 14 probes per crawled page when the page has no redirect
// surface to begin with.
//
// Sorted output keeps probe order (and therefore finding order) stable
// across runs.
func openRedirectSinks(p page.Page, u *url.URL, sweep bool) []Sink {
	type key struct {
		method string
		url    string
		loc    Loc
		name   string
	}
	seen := map[key]struct{}{}
	add := func(out []Sink, s Sink) []Sink {
		if s.Name == "" || s.URL == "" {
			return out
		}
		k := key{s.Method, s.URL, s.Loc, s.Name}
		if _, ok := seen[k]; ok {
			return out
		}
		seen[k] = struct{}{}
		return append(out, s)
	}

	var out []Sink
	for _, s := range SinksFor(p) {
		out = add(out, s)
	}
	if sweep {
		// Synthetic LocQuery sinks for the canonical names. They land on
		// the page URL itself with empty Value because they may not
		// actually exist on the request; the probe overlays a value
		// regardless.
		for _, name := range openRedirectParams {
			out = add(out, Sink{
				Method: http.MethodGet,
				URL:    p.URL,
				Loc:    LocQuery,
				Name:   name,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		if out[i].Loc != out[j].Loc {
			return out[i].Loc < out[j].Loc
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// openRedirectPathKeywords are the path substrings that flag a URL as
// "probably handles a redirect" and earn it the full canonical sweep at
// LevelDefault. Matched as case-insensitive substrings against the URL path,
// so /api/auth/callback, /admin/sso-init, and /go/redirect/123 all qualify.
// Loose by design - false positives just cost extra probes on a few pages
// per scan, where a missed real path costs a missed finding.
var openRedirectPathKeywords = []string{
	"login",
	"logout",
	"auth",
	"sso",
	"redirect",
}

func looksRedirectish(path string) bool {
	p := strings.ToLower(path)
	for _, kw := range openRedirectPathKeywords {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
}

// probe issues one no-follow request with the canary overlaid onto
// sink.Name. The request shape (GET-with-query, POST form, header,
// cookie) is decided by Sink.MutateRequest, so this function stays
// loc-agnostic and works the same for future LocForm sinks discovered
// on POST login forms.
//
// Returns a finding when ANY of the following points the victim at the
// canary host:
//   - a 3xx Location header (the classic server-driven redirect),
//   - a JavaScript navigation sink in the body (location.assign /
//     location.href / location.replace / window.location = ...),
//   - a meta-refresh tag in the body.
//
// Browser-quirk bypass forms (\\evil.example, ///evil.example,
// //target@evil.example) are normalized before host comparison so reflections
// that exploit lax server-side validation but still navigate cross-origin in
// real browsers are caught.
func (c OpenRedirect) probe(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	req, err := sink.MutateRequest(ctx, openRedirectCanary)
	if err != nil {
		return nil, err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Header sink dispatched first so the answer is a single header read;
	// the body is then loaded once for both evidence and the body-sink scan,
	// avoiding a double read when a page bounces through both channels.
	var sinkKind, sinkPayload string
	if isRedirectStatus(resp.StatusCode) {
		if loc := resp.Header.Get("Location"); openRedirectMatches(loc, openRedirectCanary) {
			sinkKind, sinkPayload = "the Location header", loc
		}
	}

	body, truncated, err := httpclient.ReadBodyCapped(resp, openRedirectBodyCap)
	if err != nil {
		return nil, err
	}
	if sinkKind == "" {
		if hit, kind := findBodyRedirectSink(body, openRedirectCanaryHost); hit != "" {
			sinkKind, sinkPayload = kind, hit
		}
	}
	if sinkKind == "" {
		return nil, nil
	}

	probeURL := req.URL.String()
	return &Finding{
		Check:    c.Name(),
		Target:   target,
		URL:      probeURL,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("Open redirect via %s ?%s=", sink.Loc, sink.Name),
		Detail: fmt.Sprintf(
			"Parameter %q (%s) is reflected unvalidated into %s. "+
				"Probe %s=%s produced: %s - an attacker can craft a link to %s that bounces victims to any external host.",
			sink.Name, sink.Loc, sinkKind, sink.Name, openRedirectCanary, sinkPayload, probeURL),
		CWE:   "CWE-601",
		OWASP: "A01:2021 Broken Access Control",
		Remediation: "Validate the redirect target against an allowlist of trusted hosts (or restrict to same-origin paths). " +
			"Never use unvalidated user input as a Location value; map opaque tokens to known destinations instead.",
		Evidence: &Evidence{
			Method:     req.Method,
			RequestURL: probeURL,
			Status:     resp.StatusCode,
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		// Dedupe per (page, loc, param): the same vulnerable page hit by the
		// crawler from many entry points is one issue per param. Including
		// the param name + loc keeps distinct vulnerabilities (e.g. both
		// `next` query and `next` form) from collapsing into a single finding.
		// Header and body sinks for the same param collapse on purpose - it's
		// one bug surfacing through two channels.
		DedupeKey: MakeKey(c.Name(), ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
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
// so absolute ("https://evil.example/x"), protocol-relative ("//evil.example/x"),
// and browser-quirk bypass forms (\\evil.example, ///evil.example, mixed
// slash/backslash) all match; same-origin paths and the userinfo-only trick
// "//evil.example@target" (where the actual host is target) do not.
func openRedirectMatches(location, canary string) bool {
	cu, err := url.Parse(canary)
	if err != nil || cu.Host == "" {
		return false
	}
	return locationTargetsHost(location, cu.Host)
}

// locationTargetsHost reports whether s, as a real browser would resolve it,
// navigates to wantHost. It tries an RFC-3986 parse first, then falls back
// to a browser-quirk normalization (backslashes -> slashes, multi-slash
// prefix collapsed to two) and reparses. This catches the gap between strict
// URL parsers and what Chrome/Edge actually do with reflected Location
// values.
//
// The userinfo-only trick "//evil.example@target" deliberately resolves to
// wantHost=target (RFC-correct, matches browsers), so a Location echoing the
// canary into userinfo of a same-origin host is NOT flagged - the victim
// stays on the target host.
func locationTargetsHost(s, wantHost string) bool {
	s = strings.TrimSpace(s)
	if s == "" || wantHost == "" {
		return false
	}
	if u, err := url.Parse(s); err == nil && strings.EqualFold(u.Host, wantHost) {
		return true
	}
	if u, err := url.Parse(normalizeBypassyRedirect(s)); err == nil && strings.EqualFold(u.Host, wantHost) {
		return true
	}
	return false
}

// normalizeBypassyRedirect rewrites browser-quirk redirect forms so url.Parse
// can extract a host:
//   - backslashes collapse to forward slashes (Chrome/Edge do this silently
//     before URL parsing; many vulnerable apps reflect "\\evil.example" raw),
//   - three-or-more leading slashes collapse to two ("///evil.example" -> "//evil.example"),
//   - the same applies to the authority that follows "scheme:".
//
// Mixed forms (\/\/host, //\/host, https:\\host) decay to "//host" or
// "scheme://host" through the same two rules.
func normalizeBypassyRedirect(s string) string {
	n := strings.ReplaceAll(s, `\`, "/")
	if i := strings.Index(n, "://"); i >= 0 {
		return n[:i+1] + collapseLeadingSlashes(n[i+1:])
	}
	return collapseLeadingSlashes(n)
}

func collapseLeadingSlashes(s string) string {
	if !strings.HasPrefix(s, "//") {
		return s
	}
	i := 0
	for i < len(s) && s[i] == '/' {
		i++
	}
	if i == 2 {
		return s
	}
	return "//" + s[i:]
}

// jsRedirectSinkRe matches a quoted string literal that flows into a
// JavaScript navigation API. Group 1 captures the literal contents (no
// quotes); the body scanner then asks whether that literal points at the
// canary host. Recognized shapes:
//
//	location.assign("...")    location.replace('...')   location.href = "..."
//	window.location = "..."   top.location.href = "..." document.location = `...`
//
// The pattern requires the canary URL inside a string literal, so static
// interpolation (location.href = baseUrl + path) does not false-positive -
// in that case the probe's reflected canary never lands in any one literal.
var jsRedirectSinkRe = regexp.MustCompile(
	`(?i)(?:\b(?:window|self|top|parent|document|globalThis)\.)?` +
		`location(?:\.(?:href|assign|replace))?` +
		`\s*(?:=|\(\s*)\s*` +
		"[`'\"]([^`'\"\\r\\n]+)[`'\"]",
)

// metaRefreshRe matches <meta http-equiv="refresh" content="0;url=..."> with
// the URL captured. Server-rendered meta refresh is a non-3xx bounce channel
// browsers honor identically to Location; many soft-redirect login flows use
// it as a fallback when JS is disabled.
var metaRefreshRe = regexp.MustCompile(
	`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*` +
		`["']\s*\d+\s*;\s*url\s*=\s*([^"']+)["']`,
)

// findBodyRedirectSink scans body for a JavaScript navigation API or a meta
// refresh whose target points at canaryHost. Returns the matched target
// string and a human-readable label for the sink kind ("a JavaScript
// navigation sink", "a meta refresh tag") when found; ("", "") otherwise.
//
// Body is scanned regardless of response status: many SPA login pages bounce
// via JS while returning 200, and a 3xx with a non-matching Location can
// still ship a JS bounce in its rendered error body.
func findBodyRedirectSink(body []byte, canaryHost string) (target, kind string) {
	if len(body) == 0 || canaryHost == "" {
		return "", ""
	}
	if hit := firstSinkMatchTargetingHost(jsRedirectSinkRe.FindAllSubmatch(body, -1), canaryHost); hit != "" {
		return hit, "a JavaScript navigation sink"
	}
	if hit := firstSinkMatchTargetingHost(metaRefreshRe.FindAllSubmatch(body, -1), canaryHost); hit != "" {
		return hit, "a meta refresh tag"
	}
	return "", ""
}

func firstSinkMatchTargetingHost(matches [][][]byte, wantHost string) string {
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(string(m[1]))
		if locationTargetsHost(v, wantHost) {
			return v
		}
	}
	return ""
}
