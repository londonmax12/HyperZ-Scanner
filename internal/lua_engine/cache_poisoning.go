package lua_engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
)

// CachePoisoning probes two classes of cache-layer bugs that share a root
// cause: the application and the cache disagree about what makes a response
// distinct.
//
//  1. Unkeyed-header poisoning. The cache stores responses keyed on
//     (host, path, query). A request header the application echoes into
//     its response but the cache does NOT include in the key (no Vary
//     entry) is a poisoning primitive: an attacker sends one crafted
//     request, the cache stores the poisoned response, every subsequent
//     victim served from cache sees attacker content. Tested headers are
//     the canonical reverse-proxy hints (X-Forwarded-Host, X-Forwarded-
//     Scheme, X-Original-URL, X-Rewrite-URL) which back-ends frequently
//     trust when generating absolute URLs or routing internally.
//
//  2. Cache deception. An authenticated page is reachable at a path
//     ending in a static-asset suffix (e.g. /account/info.css). Caches
//     in front of the application apply extension-based rules and
//     happily store what they assume is a CSS file, but the file is
//     actually the victim's account page. Subsequent crawlers - including
//     the attacker - retrieve the cached HTML.
//
// Probes only fire on pages whose baseline response carries a cache hint
// (Cache-Control max-age, an Age header, X-Cache / CF-Cache-Status, a
// Via proxy line, etc.) for the unkeyed-header arm, since without a
// shared cache in the path the worst case is local reflection rather
// than a stored poisoning. Cache deception runs on paths that look
// authentication-bearing (or every path at LevelAggressive) since the
// vulnerability is the suffix-confusion bug at the server, regardless
// of whether a particular intermediary caches today.
//
// This is an active (LevelDefault) check. Per-host rate limiting in the
// HTTP client governs probe pacing.
type CachePoisoning struct{}

const (
	// cachePoisonCanaryHost is the value carried by the X-Forwarded-Host
	// family of probes. RFC 2606's .example TLD guarantees the host is
	// unregistered; any echo of it into a response body, Location header,
	// or cookie domain is confirmed reflection rather than a coincidence.
	cachePoisonCanaryHost = "hyperz-poison.example"
	// cachePoisonCanaryPath is the value the X-Original-URL / X-Rewrite-URL
	// probes ask the server to route to. A 200-suffix path the application
	// definitely does not implement makes the success criterion (response
	// shape changed meaningfully from baseline) high-signal: if the body
	// changes when this header rides along, the back-end is honouring the
	// override.
	cachePoisonCanaryPath = "/hyperz-cache-poison-probe-9f3a"
	cachePoisonBodyCap    = 16 << 10
	// cacheDeceptionSuffix is the static-asset suffix appended to the
	// authenticated path. /style.css is the textbook example - long
	// enough that a real handler would have to opt in to it, with a
	// suffix every caching CDN ships rules for.
	cacheDeceptionSuffix = "/hyperz-probe.css"
	// cachePoisonCachebusterParam is the query parameter every unkeyed-
	// header probe appends to the canonical target URL. The whole point
	// of this check is to confirm caches that DON'T key on the suspect
	// header; if we fired the probe at the canonical (method, path,
	// query) the poisoned response we induce would land on the exact
	// cache key real victims hit. Appending a random value here moves
	// the poisoned entry to a key no organic request will reach, so the
	// only consequence of the probe is a stranded cache entry that ages
	// out at TTL. Caches configured to strip query strings from the key
	// (rare on dynamic, cache-hinted paths) will defeat the bust - the
	// arm should be gated behind an opt-in flag on hosts where that's a
	// known risk; for the general case the cachebuster is the right
	// default.
	cachePoisonCachebusterParam = "_hyperz_cb"
	// cachePoisonCachebusterBytes is the size of the random nonce
	// rendered as hex. 8 bytes (16 hex chars) is short enough to keep
	// the probe URL readable in evidence and large enough that collision
	// between concurrent scanners is negligible.
	cachePoisonCachebusterBytes = 8
)

// unkeyedHeader describes one header probe: the header to set, the value
// to send, and how to recognize a successful poisoning vector in the
// response. reflectionCheck inspects the live response and the baseline
// snapshot; canary is included in the finding detail.
type unkeyedHeader struct {
	name             string
	value            string
	canary           string
	reflectionCheck  func(resp *http.Response, body []byte, baseline snapshot) (where string, ok bool)
	deceptionMessage string
}

// cachePoisonHeaderProbes returns the headers to test. Picked for the
// most-common back-end behaviours: X-Forwarded-Host is reflected into
// canonical link tags / password-reset emails; X-Forwarded-Scheme/Proto
// flips http<>https in absolute URLs; X-Original-URL / X-Rewrite-URL are
// the IIS / .NET path-rewrite hints back-ends honour without
// authorization rechecks.
func cachePoisonHeaderProbes() []unkeyedHeader {
	hostCanary := cachePoisonCanaryHost
	pathCanary := cachePoisonCanaryPath
	return []unkeyedHeader{
		{
			name:   "X-Forwarded-Host",
			value:  hostCanary,
			canary: hostCanary,
			reflectionCheck: func(resp *http.Response, body []byte, base snapshot) (string, bool) {
				return findReflection(hostCanary, resp, body, base)
			},
			deceptionMessage: "Back-end echoes X-Forwarded-Host into the response body or absolute URLs without keying the cache on it.",
		},
		{
			name:   "X-Forwarded-Scheme",
			value:  "nothttps",
			canary: "nothttps://" + cachePoisonCanaryHost,
			reflectionCheck: func(resp *http.Response, body []byte, base snapshot) (string, bool) {
				// X-Forwarded-Scheme rewrites the protocol in generated
				// absolute URLs. The canary scheme is one no browser will
				// follow, so any nothttps:// in the response body proves
				// the header poisoned the URL generation.
				return findReflection("nothttps://", resp, body, base)
			},
			deceptionMessage: "Back-end rewrites generated absolute URLs to use the attacker-supplied scheme (X-Forwarded-Scheme).",
		},
		{
			name:   "X-Forwarded-Proto",
			value:  "nothttps",
			canary: "nothttps://",
			reflectionCheck: func(resp *http.Response, body []byte, base snapshot) (string, bool) {
				return findReflection("nothttps://", resp, body, base)
			},
			deceptionMessage: "Back-end rewrites generated absolute URLs to use the attacker-supplied scheme (X-Forwarded-Proto).",
		},
		{
			name:   "X-Original-URL",
			value:  pathCanary,
			canary: pathCanary,
			reflectionCheck: func(resp *http.Response, body []byte, base snapshot) (string, bool) {
				// Path rewrite: the back-end routes the request to a
				// different controller than the URL line said. We catch
				// this two ways - direct reflection of the canary path
				// in the response (rare), or a response that diverged
				// meaningfully from baseline (the more common signal).
				if where, ok := findReflection(pathCanary, resp, body, base); ok {
					return where, true
				}
				if responseDiverged(resp, body, base) {
					return "response shape changed vs. baseline", true
				}
				return "", false
			},
			deceptionMessage: "Back-end honours X-Original-URL to override the routed path without rechecking authorization.",
		},
		{
			name:   "X-Rewrite-URL",
			value:  pathCanary,
			canary: pathCanary,
			reflectionCheck: func(resp *http.Response, body []byte, base snapshot) (string, bool) {
				if where, ok := findReflection(pathCanary, resp, body, base); ok {
					return where, true
				}
				if responseDiverged(resp, body, base) {
					return "response shape changed vs. baseline", true
				}
				return "", false
			},
			deceptionMessage: "Back-end honours X-Rewrite-URL to override the routed path without rechecking authorization.",
		},
	}
}

// authPathKeywords flag a URL path as authentication-bearing for the
// cache-deception arm. Match is case-insensitive substring. Wider than
// strictly necessary so the check covers /api/account, /users/me/inbox,
// /admin-panel, etc. without per-app tuning. False positives just cost
// one extra request per page.
var authPathKeywords = []string{
	"account",
	"admin",
	"billing",
	"dashboard",
	"inbox",
	"manage",
	"member",
	"my-",
	"payment",
	"private",
	"profile",
	"secure",
	"settings",
	"/me",
	"/me/",
	"user",
}

// cachePoisonProbeURL returns target with a random cachebuster query
// parameter appended. See cachePoisonCachebusterParam for why the
// probe must NOT hit the canonical cache key; this helper is the only
// supported way to build an unkeyed-header probe URL.
func cachePoisonProbeURL(target string) (string, error) {
	var buf [cachePoisonCachebusterBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return appendQueryParam(target, cachePoisonCachebusterParam, hex.EncodeToString(buf[:]))
}

// probeUnkeyedHeader fires one header probe and returns a finding when
// the canary is reflected AND the cache is not keyed on the header. The
// Vary check is what separates a host-header-injection finding (per-
// request) from a cache-poisoning finding (stored, hits every cache
// consumer).
//
// The probe URL appends a random cachebuster query parameter so the
// poisoned response a vulnerable cache stores lands on a key no
// organic request will reach. Without that, the act of confirming the
// bug would itself be the poisoning attack against real users.
func (c CachePoisoning) probeUnkeyedHeader(ctx context.Context, client *httpclient.Client, target string, probe unkeyedHeader, base snapshot, vary map[string]struct{}) (*Finding, error) {
	probeTarget, err := cachePoisonProbeURL(target)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeTarget, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(probe.name, probe.value)

	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, cachePoisonBodyCap)
	if err != nil {
		return nil, err
	}
	where, ok := probe.reflectionCheck(resp, body, base)
	if !ok {
		return nil, nil
	}
	// Vary: * is the catch-all "this response is not cacheable across
	// any request variation", which suppresses the bug.
	if _, star := vary["*"]; star {
		return nil, nil
	}
	if _, keyed := vary[strings.ToLower(probe.name)]; keyed {
		return nil, nil
	}
	probeURL := req.URL.String()
	varyDesc := "none"
	if v := strings.TrimSpace(base.Headers.Get("Vary")); v != "" {
		varyDesc = v
	}
	return &Finding{
		Check:    "cache-poisoning",
		Target:   target,
		URL:      probeURL,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("Web cache poisoning via unkeyed header %s", probe.name),
		Detail: fmt.Sprintf(
			"%s The probe sent %s: %s and observed the canary at %s. "+
				"The baseline response carries cache hints (Cache-Control/Age/X-Cache) but Vary is %q, "+
				"so the intermediate cache will not partition entries on this header. "+
				"An attacker can issue one crafted request and every subsequent victim served from cache receives the poisoned response.",
			probe.deceptionMessage, probe.name, probe.value, where, varyDesc),
		CWE:   "CWE-444",
		OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Add the header to the cache key (Vary or the CDN's surrogate-key config) so a poisoned response can't be served back to other users. " +
			"Better: stop reflecting reverse-proxy hints into generated URLs - derive absolute URLs from configuration, not from request headers. " +
			"For X-Original-URL / X-Rewrite-URL specifically, ignore the header at the application layer and rely solely on the routed path.",
		Evidence: &Evidence{
			Method:     req.Method,
			RequestURL: probeURL,
			Status:     resp.StatusCode,
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		// Per-host: cache configuration is site-wide. The header name
		// disambiguates so distinct primitives (Host echo vs. path
		// rewrite) still report independently.
		DedupeKey: MakeKey("cache-poisoning", ScopeHost, target, "unkeyed-header", "name:"+strings.ToLower(probe.name)),
	}, nil
}

// probeCacheDeception appends a static-asset suffix to the path and
// fetches the result. A vulnerable server returns the same authenticated
// HTML the original path returns; an intermediate CDN treats the .css
// extension as cacheable and stores it for arbitrary retrieval.
func (c CachePoisoning) probeCacheDeception(ctx context.Context, client *httpclient.Client, target string, u *url.URL, base snapshot) (*Finding, error) {
	if !isHTMLContentType(base.Headers.Get("Content-Type")) {
		return nil, nil
	}
	deceived, err := deceptionURL(u)
	if err != nil {
		return nil, err
	}
	if deceived == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, deceived, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.DoNoFollow(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	if !isHTMLContentType(resp.Header.Get("Content-Type")) {
		return nil, nil
	}
	body, truncated, err := httpclient.ReadBodyCapped(resp, cachePoisonBodyCap)
	if err != nil {
		return nil, err
	}
	// The deception payoff is the server treating a /style.css URL as
	// if it were the authenticated path. We require the bodies to match
	// closely so we don't flag a generic catch-all 404 page that
	// happens to return 200.
	if !bodiesMatch(body, base.Body) {
		return nil, nil
	}
	// If the server explicitly forbids caching on the deception URL the
	// classic deception payoff is suppressed - the CDN should not store
	// the response. Still high-signal as a routing bug, but we drop
	// severity to Medium to reflect the diminished impact.
	sev := SeverityHigh
	if cacheControlForbidsStorage(resp.Header.Get("Cache-Control")) {
		sev = SeverityMedium
	}
	return &Finding{
		Check:    "cache-poisoning",
		Target:   target,
		URL:      deceived,
		Severity: sev,
		Title:    "Web cache deception via static-asset path suffix",
		Detail: fmt.Sprintf(
			"Appending %q to the authenticated path %q produced a 200 response whose body matched the original. "+
				"Caches in front of the application apply extension-based rules (.css, .js, .jpg are typically cacheable) and will store the response "+
				"under the deception URL. An attacker who lures a victim to /<auth-path>%[1]s causes the cache to retain the victim's authenticated HTML; "+
				"the attacker can then fetch the same URL anonymously and retrieve the stored content.",
			cacheDeceptionSuffix, u.Path),
		CWE:   "CWE-525",
		OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Reject (or 404) requests whose URL extension does not match the resource the back-end is about to return. " +
			"Configure the cache layer to respect Cache-Control: private / no-store on the upstream response rather than overriding by extension. " +
			"For deeper defense, send Cache-Control: private, no-store on every authenticated response and ensure intermediaries honour it.",
		Evidence: &Evidence{
			Method:     req.Method,
			RequestURL: deceived,
			Status:     resp.StatusCode,
			Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
		},
		// Per-page: deception is path-bound. A site can have one
		// vulnerable handler and ten safe ones; collapsing to host
		// would hide that distinction.
		DedupeKey: MakeKey("cache-poisoning", ScopePage, target, "cache-deception"),
	}, nil
}

// deceptionURL returns target with cacheDeceptionSuffix appended to the
// path. Empty path becomes "/" before suffixing so the suffix lands on
// a real segment. Returns ("", nil) when target already ends in the
// suffix - re-probing a previous probe URL would be a no-op.
func deceptionURL(u *url.URL) (string, error) {
	if u == nil {
		return "", nil
	}
	if strings.HasSuffix(u.Path, cacheDeceptionSuffix) {
		return "", nil
	}
	clone := *u
	path := strings.TrimRight(clone.Path, "/")
	// cacheDeceptionSuffix already starts with "/", so an empty path
	// (the root case) gets exactly one separator, not two.
	clone.Path = path + cacheDeceptionSuffix
	clone.RawPath = ""
	return clone.String(), nil
}

// findReflection looks for needle in the response's body and selected
// headers (Location, Link, Set-Cookie, Content-Location). It also checks
// that the needle is not already present in the baseline; an echo that
// was there before the probe is not the probe's doing.
func findReflection(needle string, resp *http.Response, body []byte, base snapshot) (string, bool) {
	if needle == "" {
		return "", false
	}
	lowerNeedle := strings.ToLower(needle)
	if len(base.Body) > 0 && strings.Contains(strings.ToLower(string(base.Body)), lowerNeedle) {
		return "", false
	}
	if len(body) > 0 && strings.Contains(strings.ToLower(string(body)), lowerNeedle) {
		return "response body", true
	}
	for _, h := range []string{"Location", "Link", "Set-Cookie", "Content-Location", "Refresh"} {
		for _, v := range resp.Header.Values(h) {
			if strings.Contains(strings.ToLower(v), lowerNeedle) {
				return h + " header", true
			}
		}
	}
	return "", false
}

// responseDiverged reports whether resp's body or status differs
// meaningfully from baseline. Used for path-rewrite probes (X-Original-
// URL / X-Rewrite-URL) where the canary path itself rarely echoes - the
// observable signal is "the response looks like a different page".
func responseDiverged(resp *http.Response, body []byte, base snapshot) bool {
	if resp.StatusCode != base.Status {
		return true
	}
	if len(body) == 0 || len(base.Body) == 0 {
		return false
	}
	// Length-difference threshold: anything >25% almost certainly means
	// a different response shape. Caching of dynamic content typically
	// produces tighter equivalence than this.
	a, b := len(body), len(base.Body)
	if a < b {
		a, b = b, a
	}
	if a-b > a/4 {
		return true
	}
	return false
}

// bodiesMatch is the cache-deception "this is the same authenticated
// page" test. Exact equality is too strict (CSRF tokens, timestamps,
// nonces rotate per-request); we accept high-similarity by length and
// matching prefix AND a middle-region anchor. Empty bodies never match
// - a zero-length 200 is the classic catch-all error page.
//
// Why the middle anchor: templated SPAs share a long HTML shell
// (doctype, head, nav) that fools a prefix-only check on any two
// pages on the site. Sampling a chunk from the middle of the shorter
// body forces the dynamic region to agree, which is where two
// semantically different pages actually diverge. The anchor is taken
// from the middle (not the tail) so rotating tokens near the bottom
// of the body - the typical CSRF / footer-timestamp location - don't
// false-negative two snapshots of the same page.
func bodiesMatch(deceived, baseline []byte) bool {
	if len(deceived) == 0 || len(baseline) == 0 {
		return false
	}
	if len(deceived) == len(baseline) {
		return string(deceived) == string(baseline)
	}
	// Allow up to 5% length drift to absorb rotating nonces / CSRF tokens.
	longer, shorter := len(deceived), len(baseline)
	if longer < shorter {
		longer, shorter = shorter, longer
	}
	if longer-shorter > longer/20 {
		return false
	}
	const anchorBytes = 256
	prefixLen := anchorBytes
	if prefixLen > shorter {
		prefixLen = shorter
	}
	if string(deceived[:prefixLen]) != string(baseline[:prefixLen]) {
		return false
	}
	// Middle anchor: centered window of anchorBytes in the shorter body,
	// taken from the same byte offset in both. When the shorter body is
	// not long enough to fit prefix + middle without overlap, the prefix
	// already covered the comparable region and we accept.
	middleStart := shorter/2 - anchorBytes/2
	if middleStart < prefixLen {
		return true
	}
	middleEnd := middleStart + anchorBytes
	if middleEnd > shorter {
		middleEnd = shorter
	}
	return string(deceived[middleStart:middleEnd]) == string(baseline[middleStart:middleEnd])
}

// cacheHintsPresent reports whether h carries any evidence that a cache
// sits in front of the application or that the response is itself
// cacheable by a downstream proxy. False negatives are fine - we will
// just skip the unkeyed-header arm on hosts without observable caching,
// which is the conservative call: a noisy poisoning report against a
// host with no cache is wrong.
func cacheHintsPresent(h http.Header) bool {
	if h == nil {
		return false
	}
	if h.Get("Age") != "" {
		return true
	}
	if h.Get("X-Cache") != "" || h.Get("X-Cache-Status") != "" {
		return true
	}
	if h.Get("CF-Cache-Status") != "" || h.Get("CF-Ray") != "" {
		return true
	}
	if h.Get("X-Varnish") != "" || h.Get("X-Drupal-Cache") != "" {
		return true
	}
	if h.Get("Via") != "" {
		return true
	}
	if h.Get("X-Served-By") != "" {
		return true
	}
	cc := strings.ToLower(h.Get("Cache-Control"))
	if cc == "" {
		return false
	}
	// Cache-Control hints that allow shared caching make a poisoning
	// outcome plausible even without a visible cache marker - some CDN
	// configs strip cache markers from public responses.
	if strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage") {
		return true
	}
	if strings.Contains(cc, "max-age") && !strings.Contains(cc, "private") && !strings.Contains(cc, "no-store") {
		return true
	}
	return false
}

// cacheControlForbidsStorage reports whether cc contains a directive that
// instructs every cache to refuse to store the response. Used to soften
// the deception-finding severity: when the upstream explicitly forbids
// storage, the deception payoff requires a misconfigured cache that
// ignores the directive.
func cacheControlForbidsStorage(cc string) bool {
	lc := strings.ToLower(cc)
	return strings.Contains(lc, "no-store") || strings.Contains(lc, "private")
}

// parseVary returns the lowercased set of headers listed in v. Vary
// fields are comma-separated header names; we compare against probe
// names with strings.ToLower(probe.name).
func parseVary(v string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, part := range strings.Split(v, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

// isAuthLikelyPath reports whether the URL path is one the cache-
// deception arm should probe at LevelDefault. False positives cost one
// extra request per page; false negatives miss real findings. The
// keyword list errs toward the former.
func isAuthLikelyPath(path string) bool {
	p := strings.ToLower(path)
	for _, kw := range authPathKeywords {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
}

// Compile-time check: CachePoisoning satisfies Check.
