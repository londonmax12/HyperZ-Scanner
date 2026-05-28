package lua_engine

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

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
