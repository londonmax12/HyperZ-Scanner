package headers

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"
)

const (
	// cspBypassBodyCap bounds bodies the check buffers - the relative
	// <script src> tags the base-uri probe inspects, and the JSONP echo
	// the whitelist probe matches. Both signals land in the first
	// kilobytes of any reasonable response; 64 KiB is generous headroom.
	cspBypassBodyCap = 64 << 10
	// cspBypassCallbackCanary is the JSONP callback name. Distinctive
	// enough that no live response will incidentally contain it; the
	// bypass is confirmed only when the endpoint echoes it as a function
	// call (canary followed by an opening paren).
	cspBypassCallbackCanary = "hyperzCspBypassCb"
)

// cspNonceRegex extracts the value portion of a 'nonce-XYZ' source. The
// keyword prefix is case-insensitive per the spec; the value itself
// is preserved verbatim so subsequent equality checks match the bytes
// the server actually emitted.
var cspNonceRegex = regexp.MustCompile(`(?i)'nonce-([^']+)'`)

// cspScriptSrcRelativeRegex finds <script src="..."> tags whose URL is
// relative to the document base (no scheme, no protocol-relative "//").
// Anchored on the src attribute so style/link tags with similar shapes
// do not get mixed in - those are a separate bypass surface and we are
// not probing them here.
var cspScriptSrcRelativeRegex = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)

// jsonpProbe pairs a CDN host with a JSONP endpoint URL fragment ending
// in "callback=" - the probe appends the canary callback name and inspects
// the response. Curated to endpoints documented as JSONP-bypass vectors
// in published CSP research and csp-evaluator's host_source_bypasses
// list. New entries should be (a) publicly accessible without auth,
// (b) state-free (idempotent GET), and (c) confirmable by callback echo.
type jsonpProbe struct {
	host    string
	urlTmpl string
}

var jsonpProbes = []jsonpProbe{
	{
		host:    "ajax.googleapis.com",
		urlTmpl: "https://ajax.googleapis.com/ajax/services/feed/find?v=1.0&q=hyperz&callback=",
	},
	{
		host:    "www.google.com",
		urlTmpl: "https://www.google.com/complete/search?client=chrome&q=hyperz&callback=",
	},
	{
		host:    "www.youtube.com",
		urlTmpl: "https://www.youtube.com/oembed?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DjNQXAC9IVRw&format=json&callback=",
	},
	{
		host:    "accounts.google.com",
		urlTmpl: "https://accounts.google.com/o/oauth2/revoke?callback=",
	},
}

// nonceValues returns the unique nonce VALUES (the bit after "nonce-")
// appearing in script-src and style-src. Both directives are inspected
// because reuse in either is a fatal policy defect, and a site that
// rotates one but not the other still has the inline-style-injection
// half of the bypass available.
func nonceValues(dirs map[string][]string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, name := range []string{"script-src", "style-src"} {
		for _, src := range dirs[name] {
			m := cspNonceRegex.FindStringSubmatch(src)
			if len(m) < 2 {
				continue
			}
			v := m[1]
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// baseURIIsHijackable returns true when the CSP either omits base-uri
// entirely or includes a wildcard / scheme-only token that still lets
// an attacker point <base href> at an arbitrary host. base-uri does
// NOT inherit from default-src, so absence alone is enough.
func baseURIIsHijackable(dirs map[string][]string) bool {
	v, present := dirs["base-uri"]
	if !present {
		return true
	}
	for _, s := range v {
		ls := strings.ToLower(strings.TrimSpace(s))
		if ls == "*" || ls == "https:" || ls == "http:" || ls == "data:" {
			return true
		}
	}
	return false
}

// cspScriptSrcAllowsHost reports whether any source in sources would
// allow loading a script from candidateHost over HTTPS. Implements the
// subset of CSP source matching the JSONP probe needs:
//
//   - bare "*" trusts everything
//   - "https:" / "http:" (scheme-only) trusts every host on that scheme
//   - "*.domain.tld" matches any subdomain of domain.tld (and the apex,
//     per the CSP spec)
//   - "host[:port]" / "scheme://host[:port][/path]" must match host exactly
//
// Returns the original source string that matched so the finding can
// quote the exact CSP token responsible. Quoted keywords ('self',
// nonces, hashes) are skipped - they do not allow third-party hosts.
func cspScriptSrcAllowsHost(sources []string, candidateHost string) (string, bool) {
	cand := strings.ToLower(candidateHost)
	for _, raw := range sources {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "'") {
			continue
		}
		if s == "*" {
			return raw, true
		}
		if s == "https:" || s == "http:" {
			return raw, true
		}
		host := hostOfCSPSource(s)
		if host == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			// "*.example.com" matches any subdomain, and per the CSP
			// spec also the apex "example.com".
			suffix := host[1:] // ".example.com"
			apex := host[2:]   // "example.com"
			if strings.HasSuffix(cand, suffix) || cand == apex {
				return raw, true
			}
			continue
		}
		if host == cand {
			return raw, true
		}
	}
	return "", false
}

// hostOfCSPSource pulls the host portion of a CSP source value. Accepts
// "host", "host:port", "scheme://host", "scheme://host:port",
// "host/path", etc. The port is stripped (probes target the default 443).
// Returns empty when the value cannot be coerced into a host (e.g. a
// scheme-only token, which is handled earlier as a special case).
func hostOfCSPSource(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i != -1 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i != -1 {
		port := s[i+1:]
		if port == "*" || isAllDigits(port) {
			s = s[:i]
		}
	}
	return s
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// confirmsJSONP returns true when ct is a JavaScript content type AND
// body contains the canary callback name immediately followed by an
// opening paren. The function-call shape is what makes the response
// JSONP - a JSON error body that merely mentions the callback name as
// a string would otherwise false-positive (e.g. {"error":"bad callback
// hyperzCspBypassCb"}), and we want only confirmed bypasses.
func confirmsJSONP(ct string, body []byte, canary string) bool {
	c := strings.ToLower(strings.TrimSpace(ct))
	jsCT := strings.HasPrefix(c, "application/javascript") ||
		strings.HasPrefix(c, "text/javascript") ||
		strings.HasPrefix(c, "application/x-javascript")
	if !jsCT {
		return false
	}
	return bytes.Contains(body, []byte(canary+"("))
}

func jsonpEvidenceSnippet(body []byte, truncated bool) string {
	const max = 200
	s := string(body)
	if len(s) > max {
		s = s[:max] + "..."
	}
	if truncated {
		s += " [body cap reached]"
	}
	return s
}

// isAbsoluteOrProtocolRelative reports whether src has a scheme or is
// "//host/..." - the cases base-uri hijack does NOT affect because the
// target origin is fully specified by the URL itself.
func isAbsoluteOrProtocolRelative(src string) bool {
	if strings.HasPrefix(src, "//") {
		return true
	}
	if i := strings.Index(src, ":"); i > 0 {
		head := src[:i]
		for _, r := range head {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.') {
				return false
			}
		}
		return true
	}
	return false
}

// appendQueryParam returns rawurl with key=val added to its query
// string. Used by the nonce-reuse probe to bust intermediary caches on
// the second fetch.
func appendQueryParam(rawurl, key, val string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

