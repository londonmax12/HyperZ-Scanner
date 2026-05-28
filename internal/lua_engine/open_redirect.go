package lua_engine

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

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
