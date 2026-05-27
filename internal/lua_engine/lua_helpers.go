package lua_engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/page"
)

// This file exposes the small set of pure helpers the Lua bridge calls
// into from ported checks. The wrapped originals stay unexported on the
// Go-check side so the package's public surface does not balloon with
// names a non-bridge caller has no reason to use; each wrapper is a
// one-line forward so a Go-side refactor of the underlying helper
// automatically propagates to every Lua port.
//
// Categories:
//   * IsHTMLContentType / IsScannableContentType - Content-Type filters
//     shared by half the passive checks; the Lua ports re-use them so a
//     change to "what counts as HTML" lands once, in Go.
//   * ParseSetCookies - lifts the http.Response.Cookies() helper out
//     onto a bare http.Header so the cookie-attributes Lua port does
//     not have to build a fake *http.Response.
//   * ParseHSTSDirectives - exposes the HSTS-weak parser shape (split
//     directives + structural parse errors) so the Lua port consumes
//     the same parser the Go check does.
//   * ScanSecretsInBody / RedactSecret - the secrets-in-body scanner +
//     redactor; the pattern catalogue stays in Go because it is 440
//     lines of regex no Lua author should re-implement.
//   * IterHTMLTags / ResolveURLRef - the tokenizer-and-resolve pair the
//     HTML-walking ports (sri-missing, target-blank-noopener, form-
//     autocomplete) use to iterate document tags without each
//     reimplementing the same html.Tokenizer loop in Lua.
//   * SourceMapKind / FindSourceMapReference / LooksLikeSourceMap /
//     ResolveSourceMapURL - the per-stage helpers the source-map-
//     exposure port re-uses so the regex anchors stay in one place.

// IsHTMLContentType reports whether ct names an HTML document. Wrapper
// over the package-private isHTMLContentType used by every passive
// check that gates on "only run for HTML responses".
func IsHTMLContentType(ct string) bool { return isHTMLContentType(ct) }

// IsScannableContentType reports whether ct is a text-shaped body that
// is worth running the secret-pattern scanner over. Binary types
// (images, fonts, archives) are filtered out so the regex sweep is not
// wasted on bytes that can not legitimately carry a credential string.
func IsScannableContentType(ct string) bool { return isScannableContentType(ct) }

// ParseSetCookies returns the cookies represented by the Set-Cookie
// headers on h, in the order net/http parses them. Re-uses
// http.Response.Cookies so the parse behavior is the same one cookie-
// handling code in this repo already relies on; the synthetic Response
// is throwaway, only its Header field is consulted.
func ParseSetCookies(h http.Header) []*http.Cookie {
	return (&http.Response{Header: h}).Cookies()
}

// HSTSDirectives is the parsed form of one Strict-Transport-Security
// header value: lower-cased directive name -> value (empty for flag-
// only directives) plus the structural parse errors the spec considers
// fatal (duplicate directive names).
type HSTSDirectives struct {
	Directives map[string]string
	Errors     []HSTSParseError
}

// HSTSParseError mirrors hstsParseError. Exported so the Lua port can
// iterate over the same parser output the Go check does.
type HSTSParseError struct {
	ID     string
	Detail string
}

// ParseHSTSHeader wraps the package-private parseHSTS so the Lua hsts-
// weak port consumes the exact same directive-split + duplicate-detect
// logic the Go check runs.
func ParseHSTSHeader(value string) HSTSDirectives {
	d, errs := parseHSTS(value)
	out := HSTSDirectives{Directives: d}
	for _, e := range errs {
		out.Errors = append(out.Errors, HSTSParseError{ID: e.id, Detail: e.detail})
	}
	return out
}

// SecretHit is one match the secret scanner found in a body. Pattern
// metadata is exposed verbatim so the Lua port can build the per-hit
// detail strings the Go check produces; Raw is the un-redacted bytes
// (caller is expected to redact before they reach the report) and
// Count collapses repeat hits of the same exact token in the same
// body.
type SecretHit struct {
	ID       string
	Label    string
	Severity Severity
	Raw      string
	Count    int
}

// ScanSecretsInBody runs the full secret-pattern catalogue over body
// and returns hits in the same (severity desc, id, redacted form)
// order the Go check produces. The Lua port consumes this directly
// and only owns the surrounding orchestration (Detail lead-in, title,
// dedupe key composition).
func ScanSecretsInBody(body []byte) []SecretHit {
	if len(body) == 0 {
		return nil
	}
	type key struct{ id, raw string }
	seen := map[key]*secretHit{}
	for _, pat := range secretPatterns {
		matches := pat.re.FindAllIndex(body, -1)
		for _, m := range matches {
			if pat.contextRE != nil && !hasNearbyContext(body, m[0], m[1], pat.contextRE) {
				continue
			}
			raw := string(body[m[0]:m[1]])
			k := key{id: pat.id, raw: raw}
			if h, ok := seen[k]; ok {
				h.count++
				continue
			}
			seen[k] = &secretHit{pattern: pat, raw: raw, count: 1}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	hits := make([]*secretHit, 0, len(seen))
	for _, h := range seen {
		hits = append(hits, h)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		ri := SeverityRank(hits[i].pattern.severity)
		rj := SeverityRank(hits[j].pattern.severity)
		if ri != rj {
			return ri > rj
		}
		if hits[i].pattern.id != hits[j].pattern.id {
			return hits[i].pattern.id < hits[j].pattern.id
		}
		return redactSecret(hits[i].raw) < redactSecret(hits[j].raw)
	})
	out := make([]SecretHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, SecretHit{
			ID:       h.pattern.id,
			Label:    h.pattern.label,
			Severity: h.pattern.severity,
			Raw:      h.raw,
			Count:    h.count,
		})
	}
	return out
}

// RedactSecret returns the safe-to-print form of raw. Lua port calls
// this once per hit so the redaction rule (first/last four chars,
// PEM header pass-through, full-mask for short values) only lives in
// the Go side.
func RedactSecret(raw string) string { return redactSecret(raw) }

// HTMLTag is one tokenizer-emitted start (or self-closing) tag. Attrs
// preserves attribute order so a check that needs to distinguish
// duplicate attribute names (browsers take the first) sees the same
// order html.Tokenizer reports.
type HTMLTag struct {
	Name  string
	Attrs []HTMLAttr
}

// HTMLAttr is one attribute on an HTMLTag. Name is lower-cased to
// match the case-insensitive way browsers compare HTML attribute
// names; Value is preserved verbatim so the Lua port can echo it back
// in finding text.
type HTMLAttr struct {
	Name  string
	Value string
}

// IterHTMLTags walks body once and returns every start / self-closing
// tag whose lower-cased name is in interesting. interesting may be nil
// to emit every tag, but every existing Lua port supplies a small set
// so the bridge does not allocate one HTMLTag per <div>.
//
// Attribute names are lower-cased; values are preserved as the
// tokenizer reports them. The walker silently ignores end-tag tokens,
// text, comments, and doctype - the consumers all want "the start
// shape of tags I care about" and would discard the rest anyway.
func IterHTMLTags(body []byte, interesting map[string]bool) []HTMLTag {
	if len(body) == 0 {
		return nil
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	var out []HTMLTag
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		tag := string(name)
		if interesting != nil && !interesting[tag] {
			continue
		}
		var attrs []HTMLAttr
		if hasAttr {
			for {
				k, v, more := z.TagAttr()
				attrs = append(attrs, HTMLAttr{
					Name:  strings.ToLower(string(k)),
					Value: string(v),
				})
				if !more {
					break
				}
			}
		}
		out = append(out, HTMLTag{Name: tag, Attrs: attrs})
	}
	return out
}

// ResolveURLRef returns the absolute form of ref when interpreted
// relative to base. Returns ok=false for refs the Lua port should
// skip (empty, javascript:, data:, mailto:, tel:, fragment-only) so a
// single boundary check in the Go side keeps the per-port skip lists
// from drifting out of sync.
func ResolveURLRef(base, ref string) (resolved *url.URL, ok bool) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return nil, false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "blob:") ||
		strings.HasPrefix(lower, "#") {
		return nil, false
	}
	b, err := url.Parse(base)
	if err != nil {
		return nil, false
	}
	r, err := url.Parse(trimmed)
	if err != nil {
		return nil, false
	}
	res := b.ResolveReference(r)
	if res.Host == "" {
		return nil, false
	}
	return res, true
}

// SourceMapKind reports whether ct names a JavaScript / CSS response
// the source-map-exposure check should consider, and which family the
// hit belongs to ("js" or "css"). Returns ("", false) for everything
// else so the caller can short-circuit on the bool.
func SourceMapKind(ct string) (string, bool) { return sourceMappableKind(ct) }

// FindSourceMapReference returns the sourceMappingURL value the
// response advertises (header first, then trailing comment), or ""
// when none is present. kind picks the body comment regex flavor
// (js vs css) and must come from SourceMapKind for parity.
func FindSourceMapReference(h http.Header, body []byte, kind string) string {
	return findSourceMapReference(h, body, kind)
}

// LooksLikeSourceMap reports whether body's leading bytes look like a
// Source Map v3 document (the "version" + "sources"/"mappings"
// triple-anchor). Used by the source-map-exposure port after it
// fetches the referenced URL.
func LooksLikeSourceMap(body []byte) bool { return looksLikeSourceMap(body) }

// ResolveSourceMapURL turns a (possibly relative) sourceMappingURL
// ref into the absolute http(s) URL the browser would fetch.
// Mirrors the source-map-exposure-internal resolveSourceMapURL so the
// Lua port gets the same scheme + host validation.
func ResolveSourceMapURL(base, ref string) (string, error) {
	return resolveSourceMapURL(base, ref)
}

// JSLibHit is one library identified in an HTML body's <script src>
// tags. Vulnerabilities is non-empty when the matched version maps to
// a known-bad row in the library's vulnerable-version table; otherwise
// the row is informational ("library detected, no known vulns").
type JSLibHit struct {
	Name            string
	Version         string
	Vulnerabilities []string
}

// ScanScriptTagsForKnownJSLibraries walks body for <script src=...> tags, identifies
// each script URL against the JS-library fingerprint catalogue, and
// returns one entry per detected library. The catalogue + regex match
// stay in Go; the Lua port consumes the typed result. Map iteration
// in the underlying scanner is non-deterministic, so the returned
// slice is sorted by name to keep the Lua port emitting stable order
// across runs.
func ScanScriptTagsForKnownJSLibraries(body []byte) []JSLibHit {
	detected := extractLibraries(string(body))
	if len(detected) == 0 {
		return nil
	}
	names := make([]string, 0, len(detected))
	for n := range detected {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]JSLibHit, 0, len(names))
	for _, n := range names {
		d := detected[n]
		out = append(out, JSLibHit{
			Name:            n,
			Version:         d.version,
			Vulnerabilities: append([]string{}, d.vulnerabilities...),
		})
	}
	return out
}

// CSPWeakness is one (directive, weakness) pair the CSP analyzer
// produced. id is a short stable token used as a per-finding dedupe
// suffix so the same weakness on the same host re-emits the same key.
type CSPWeakness struct {
	Directive string
	Severity  Severity
	ID        string
	Detail    string
}

// AnalyzeCSP runs the full CSP-weak analysis pass against enforcing
// + reportOnly header values and returns the deduplicated, sorted
// weakness list the Go check produces. Both arguments are the raw
// header value sets (http.Header.Values shape); pass an empty slice
// when the header is absent. Returns nil when neither header is
// present, matching the Go check's "absence is security-headers'
// job" short-circuit.
func AnalyzeCSP(enforcing, reportOnly []string) []CSPWeakness {
	if len(enforcing) == 0 && len(reportOnly) == 0 {
		return nil
	}
	var (
		policyHeader string
		isReportOnly bool
	)
	if len(enforcing) > 0 {
		policyHeader = enforcing[0]
	} else {
		policyHeader = reportOnly[0]
		isReportOnly = true
	}
	directives := parseCSP(policyHeader)
	var weaknesses []cspWeakness
	weaknesses = append(weaknesses, analyzeScriptSrc(directives)...)
	weaknesses = append(weaknesses, analyzeStyleSrc(directives)...)
	weaknesses = append(weaknesses, analyzeObjectSrc(directives)...)
	weaknesses = append(weaknesses, analyzeBaseURI(directives)...)
	weaknesses = append(weaknesses, analyzeFrameAncestors(directives)...)
	weaknesses = append(weaknesses, analyzeFormAction(directives)...)
	if isReportOnly {
		weaknesses = append(weaknesses, cspWeakness{
			directive: "<policy>",
			severity:  SeverityMedium,
			id:        "report-only-only",
			detail:    "Only Content-Security-Policy-Report-Only is set; the browser collects violation reports but does not block any of the policy's would-be denials. Until the policy is delivered via Content-Security-Policy as well, none of the CSP-based XSS / framing defenses below are actually enforced.",
		})
	}
	if len(enforcing) > 1 {
		weaknesses = append(weaknesses, cspWeakness{
			directive: "<policy>",
			severity:  SeverityLow,
			id:        "multiple-csp-headers",
			detail:    fmt.Sprintf("Response carries %d Content-Security-Policy headers. Browsers intersect them, so the effective policy is the most restrictive of all directives across the headers - which is rarely what authors intend and tends to mask which directive is doing the blocking. Consolidate to a single CSP header.", len(enforcing)),
		})
	}
	if len(weaknesses) == 0 {
		return nil
	}
	sort.SliceStable(weaknesses, func(i, j int) bool {
		if weaknesses[i].directive != weaknesses[j].directive {
			return weaknesses[i].directive < weaknesses[j].directive
		}
		return weaknesses[i].id < weaknesses[j].id
	})
	out := make([]CSPWeakness, 0, len(weaknesses))
	for _, w := range weaknesses {
		out = append(out, CSPWeakness{
			Directive: w.directive,
			Severity:  w.severity,
			ID:        w.id,
			Detail:    w.detail,
		})
	}
	return out
}

// CSPIsReportOnly tells the Lua port whether AnalyzeCSP analyzed the
// report-only policy (because the enforcing header was absent). The
// .lua port uses this to shape the title suffix and lead-in without
// re-implementing the "which header did we just analyze" decision the
// Go check makes inside Run.
func CSPIsReportOnly(enforcing, reportOnly []string) bool {
	return len(enforcing) == 0 && len(reportOnly) > 0
}

// CSPParseDirectivesLua exposes the package-private parseCSP so the
// csp-bypass Lua port consumes the same first-occurrence-wins splitter
// the active probes use to read script-src / style-src / base-uri.
// Returns directive -> source-list. Directive names are lower-cased;
// source tokens preserve their case so nonce / hash byte-equality
// checks downstream stay exact.
func CSPParseDirectivesLua(header string) map[string][]string {
	return parseCSP(header)
}

// CSPNonceValuesLua exposes nonceValues so the csp-bypass Lua port
// finds the same nonce VALUES (the bit after "nonce-") in script-src
// and style-src that the Go probe compares across two responses.
func CSPNonceValuesLua(dirs map[string][]string) []string {
	return nonceValues(dirs)
}

// CSPBaseURIHijackableLua exposes baseURIIsHijackable so the Lua port
// decides "missing or permissive base-uri" the same way the Go probe
// does. true means the precondition for the <base href> hijack holds
// and the body sweep is worth running.
func CSPBaseURIHijackableLua(dirs map[string][]string) bool {
	return baseURIIsHijackable(dirs)
}

// CSPScriptSrcAllowsHostLua exposes cspScriptSrcAllowsHost so the JSONP
// probe arm gates on the same host-matching rules (bare *, scheme-only,
// wildcard subdomain incl. apex, host[:port], scheme://host[:port][/path],
// keywords ignored). Returns the original source token that matched and
// a bool, mirroring the Go signature so the Lua port can quote the exact
// CSP token responsible in finding detail.
func CSPScriptSrcAllowsHostLua(sources []string, candidateHost string) (string, bool) {
	return cspScriptSrcAllowsHost(sources, candidateHost)
}

// CSPConfirmsJSONPLua exposes confirmsJSONP so the JSONP probe arm
// applies the same JS-content-type + canary-followed-by-paren rule to
// decide a JSONP echo is conclusive. canary is the per-probe callback
// name embedded in the request.
func CSPConfirmsJSONPLua(contentType string, body []byte, canary string) bool {
	return confirmsJSONP(contentType, body, canary)
}

// CSPBypassRelativeScriptSrcsLua extracts unique relative <script src>
// values from body in sorted order. Skips absolute (scheme:) and
// protocol-relative (//) srcs - those are not affected by a <base href>
// hijack and were never the bug. The Lua port reads this list to gate
// the base-uri-hijack finding on whether the page actually depends on
// relative loads.
func CSPBypassRelativeScriptSrcsLua(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	matches := cspScriptSrcRelativeRegex.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
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
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

// CSPIsAbsoluteOrProtocolRelativeLua exposes isAbsoluteOrProtocolRelative
// so authors of additional CSP-related Lua checks can use the same
// scheme-or-//-detection without re-implementing it.
func CSPIsAbsoluteOrProtocolRelativeLua(src string) bool {
	return isAbsoluteOrProtocolRelative(src)
}

// CSPBypassAppendQueryParamLua exposes appendQueryParam so the Lua
// nonce-reuse probe builds the same cache-busting URL the Go check
// uses. The Lua side already has url.Parse + url:string assembly via
// the bridge, but using the Go-side helper here guarantees byte-for-
// byte identical re-fetch URLs across implementations.
func CSPBypassAppendQueryParamLua(rawurl, key, val string) (string, error) {
	return appendQueryParam(rawurl, key, val)
}

// CSPBypassJSONPProbeLua is one entry from the JSONP-CDN catalogue the
// active csp-bypass JSONP arm walks. The .lua port reads the current
// snapshot of jsonpProbes via CSPBypassJSONPProbesLua so a test that
// swaps the table (overrideJSONPProbes) flips both implementations to
// the test endpoint in lockstep.
type CSPBypassJSONPProbeLua struct {
	Host    string
	URLTmpl string
}

// CSPBypassJSONPProbesLua returns the live jsonpProbes table as a
// flat slice. Reading on every call (rather than caching) means a
// test-time table swap is observed immediately by the Lua port.
func CSPBypassJSONPProbesLua() []CSPBypassJSONPProbeLua {
	out := make([]CSPBypassJSONPProbeLua, 0, len(jsonpProbes))
	for _, p := range jsonpProbes {
		out = append(out, CSPBypassJSONPProbeLua{Host: p.host, URLTmpl: p.urlTmpl})
	}
	return out
}

// CSPBypassCallbackCanaryLua / CSPBypassBodyCapLua expose the JSONP
// canary callback name and the per-probe body cap so the Lua port
// stamps the same values the Go check uses. Constants only - no
// authoring surface for changing them, which is the point.
func CSPBypassCallbackCanaryLua() string { return cspBypassCallbackCanary }
func CSPBypassBodyCapLua() int           { return cspBypassBodyCap }

// JSONPEvidenceSnippetLua exposes jsonpEvidenceSnippet so the Lua port
// builds an identical evidence snippet (200-byte truncation + cap-
// reached suffix). Keeping it in Go means a future tweak to the
// snippet length / shape lands once.
func JSONPEvidenceSnippetLua(body []byte, truncated bool) string {
	return jsonpEvidenceSnippet(body, truncated)
}

// SetTLSAuditNowForTest swaps the package-level tlsAuditNow indirection
// so the checks_lua parity tests can freeze "now" for both
// implementations from outside the checks package. Mirrors the
// withFrozenNow helper used inside the package's own tests.
func SetTLSAuditNowForTest(now time.Time) (restore func()) {
	prev := tlsAuditNow
	tlsAuditNow = func() time.Time { return now }
	return func() { tlsAuditNow = prev }
}

// SetTLSAuditDialForTest swaps the package-level tlsAuditDial
// indirection so the bridge surface can route through a synthetic
// dialer in tests that need a mocked ConnectionState (none today, but
// the seam is here for the same reason as the now setter - parity
// tests should not need to reach into private state).
func SetTLSAuditDialForTest(dial func(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error)) (restore func()) {
	prev := tlsAuditDial
	tlsAuditDial = dial
	return func() { tlsAuditDial = prev }
}

// TLSAuditExpiryUrgentWindowSeconds / TLSAuditExpirySoonWindowSeconds /
// TLSAuditDialTimeoutSeconds expose the per-check timing knobs so the
// Lua port computes the same "within 14 days" / "within 30 days" bands
// the Go check uses. Constants only - changing them is a Go-side
// decision the Lua port follows.
func TLSAuditExpiryUrgentWindowSeconds() int { return int(tlsExpiryUrgentWindow / time.Second) }
func TLSAuditExpirySoonWindowSeconds() int   { return int(tlsExpirySoonWindow / time.Second) }
func TLSAuditDialTimeoutSeconds() int        { return int(tlsDialTimeout / time.Second) }

// TLSAuditNowUnix returns the current time (post-injection) as Unix
// seconds. Bridge surfaces ctx.tls.now() on top of this so a frozen-
// now test on the Go side flips the Lua port's clock in lockstep.
func TLSAuditNowUnix() int64 { return tlsAuditNow().Unix() }

// TLSAuditVersionLabel returns the human-readable name of a negotiated
// TLS / SSL protocol version. Empty for modern (TLS 1.2 / 1.3) so the
// Lua port can decide "modern, emit nothing" with a single empty
// check. Names match the Go check's switch cases byte-for-byte.
func TLSAuditVersionLabel(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return ""
}

// TLSAuditCipherSuiteName wraps tls.CipherSuiteName so the Lua port
// reads the same canonical name strings the Go check stamps onto
// findings. Empty for unknown suite ids.
func TLSAuditCipherSuiteName(id uint16) string { return tls.CipherSuiteName(id) }

// TLSAuditIsInsecureCipher exposes the cipher-classification rule the
// Go check uses (name-substring scan over RC4 / 3DES / DES / NULL /
// EXPORT / ANON / _CBC_ / TLS_RSA_WITH_). The Lua port decides
// severity above this (HIGH for RC4/3DES/NULL/EXPORT/ANON, MEDIUM for
// CBC / static-RSA) using the same name string.
func TLSAuditIsInsecureCipher(id uint16) bool { return isInsecureCipher(id) }

// TLSAuditHandshakeResultLua is the per-handshake snapshot the Lua tls
// bridge hands back to the .lua port. Mirrors the load-bearing fields
// of tls.ConnectionState plus the SCT-extension flag for each peer
// cert; everything finding-shape (severity bands, dedupe-key parts,
// remediation text) is composed Lua-side.
type TLSAuditHandshakeResultLua struct {
	Version              uint16
	VersionLabel         string
	CipherSuite          uint16
	CipherSuiteName      string
	IsInsecureCipher     bool
	OCSPResponsePresent  bool
	HandshakeSCTNonEmpty bool
	PeerCertificates     []*x509.Certificate
}

// TLSAuditHandshakeLua performs the same single passive TLS handshake
// TLSAudit.Run does and returns the per-cert + per-connection fields
// the Lua port needs. Goes through the same tlsAuditDial indirection
// so tests can intercept; honors the host's SNI server name unless an
// override is passed.
func TLSAuditHandshakeLua(ctx context.Context, addr, serverName string) (*TLSAuditHandshakeResultLua, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	conn, err := tlsAuditDial(ctx, addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	out := &TLSAuditHandshakeResultLua{
		Version:              state.Version,
		VersionLabel:         TLSAuditVersionLabel(state.Version),
		CipherSuite:          state.CipherSuite,
		CipherSuiteName:      TLSAuditCipherSuiteName(state.CipherSuite),
		IsInsecureCipher:     TLSAuditIsInsecureCipher(state.CipherSuite),
		OCSPResponsePresent:  len(state.OCSPResponse) > 0,
		HandshakeSCTNonEmpty: hasNonEmptySCT(state.SignedCertificateTimestamps),
		PeerCertificates:     state.PeerCertificates,
	}
	return out, nil
}

// TLSAuditCertEmbedsSCT exposes leafEmbedsSCT. The Lua port falls back
// on this when the handshake delivered no SCTs - a publicly-trusted
// cert that embeds SCTs in the X509v3 extension still satisfies CT
// compliance.
func TLSAuditCertEmbedsSCT(cert *x509.Certificate) bool { return leafEmbedsSCT(cert) }

// TLSAuditCertVerifyHostname mirrors *x509.Certificate.VerifyHostname
// returning true when the cert covers host. Wrapped so the .lua port
// produces an ok-bool without each call site marshalling an error
// shape Lua would just throw away.
func TLSAuditCertVerifyHostname(cert *x509.Certificate, host string) bool {
	if cert == nil {
		return false
	}
	return cert.VerifyHostname(host) == nil
}

// WSAuditDiscoverEndpointsLua wraps discoverWSEndpoints so the ws-audit
// Lua port pulls ws:// / wss:// URL literals out of a body using the
// exact same regex + dedupe + sort the Go check does. Returns the
// sorted, deduped slice of absolute endpoint URLs.
func WSAuditDiscoverEndpointsLua(body []byte) []string {
	return discoverWSEndpoints(page.Page{Body: body})
}

// WSAuditHandshakeResultLua is the per-handshake outcome the ws bridge
// hands back to the .lua port. Mirrors wsHandshake's four-return shape
// in a single struct so the bridge surface is one helper, not four
// loose values to thread through Lua.
type WSAuditHandshakeResultLua struct {
	Accepted bool
	Snippet  string
	Status   int
}

// WSAuditHandshakeLua wraps wsHandshake. Returns Accepted=true only
// when the server returned 101 Switching Protocols and the
// Sec-WebSocket-Accept derived correctly from the bridge's
// per-handshake key - the same two-gate rule the Go check uses to
// distinguish a real WS server from a coincidentally-101 proxy.
//
// origin is the Origin header the handshake carries. Pass
// WSAuditForeignOriginLua() to mirror the Go CSWSH probe; an empty
// string drops the Origin header entirely.
func WSAuditHandshakeLua(ctx context.Context, target, origin string) (*WSAuditHandshakeResultLua, error) {
	accepted, snippet, status, err := wsHandshake(ctx, target, origin)
	if err != nil {
		return nil, err
	}
	return &WSAuditHandshakeResultLua{
		Accepted: accepted,
		Snippet:  snippet,
		Status:   status,
	}, nil
}

// WSAuditForeignOriginLua exposes wsOrigin so the .lua port stamps
// the same foreign-Origin string into detail / wire as the Go check.
// Constant - the value is well-known (example-domain hostname) so
// findings on this never collide with a real allowlist.
func WSAuditForeignOriginLua() string { return wsOrigin }

// WSAuditMaxEndpointsPerPageLua exposes wsMaxEndpointsPerPage so the
// .lua port caps the per-page probe fan-out at the same number the Go
// check does. A test that tightens the cap (mass-endpoint stress) only
// needs to change the Go constant.
func WSAuditMaxEndpointsPerPageLua() int { return wsMaxEndpointsPerPage }

// OverrideCSPBypassJSONPProbesForTest swaps the package-private
// jsonpProbes table for the duration of a parity test and returns a
// restore func. The checks_lua tests use this to point both the Go
// check and (transitively through CSPBypassJSONPProbesLua) the Lua
// port at a httptest endpoint without each test reaching into the
// private slice directly.
func OverrideCSPBypassJSONPProbesForTest(probes []CSPBypassJSONPProbeLua) (restore func()) {
	prev := jsonpProbes
	jsonpProbes = make([]jsonpProbe, len(probes))
	for i, p := range probes {
		jsonpProbes[i] = jsonpProbe{host: p.Host, urlTmpl: p.URLTmpl}
	}
	return func() { jsonpProbes = prev }
}

// SQLiErrorNewMatches returns the SQL-driver error patterns that
// appear in body but did not appear in baseline. The pattern catalogue
// lives in Go (sqli_error.go's SQLErrorPatterns); the Lua port owns
// the orchestration (baseline send, per-payload probe, finding shape).
// Each result is the matched pattern name so the Lua side can stamp
// it into the per-finding detail.
func SQLiErrorNewMatches(body, baseline []byte) []string {
	return subtractPatterns(matchSQLPatterns(body), matchSQLPatterns(baseline))
}

// FormActionCandidate is one (action, originating-form) pair the
// form-action-insecure parser produced. Resolved is the absolute URL
// the browser would submit to (after applying any <base href>); Raw
// is the attribute text as the document carried it (kept for the
// per-finding detail). Method is uppercase ("GET" / "POST"). Override
// is true for candidates produced by a <button formaction> or
// <input formaction> rather than the parent <form>'s own action.
// Inputs is the form's input inventory; HasCredentialField records
// whether any input matched the sensitive-name heuristic, so the Lua
// port can branch on severity / title without re-walking the list.
type FormActionCandidate struct {
	Raw                string
	Resolved           string
	Method             string
	Override           bool
	Inputs             []FormActionInput
	HasCredentialField bool
}

// FormActionInput is one named field on the parent form. Sensitive is
// true when name + type triggered the credential-shape heuristic.
type FormActionInput struct {
	Name      string
	Type      string
	Sensitive bool
}

// ScanFormActions walks body once and returns one FormActionCandidate
// per <form action> + per <button formaction> / <input formaction>
// override the document carries. baseURL drives relative resolution
// (and is updated when a <base href> is observed in document order).
// Non-network actions (javascript:, mailto:, fragment, ...) are
// filtered out; the Lua port iterates the remaining candidates and
// emits a finding for each whose Resolved is http://.
func ScanFormActions(body []byte, baseURL string) []FormActionCandidate {
	pageURL, err := url.Parse(baseURL)
	if err != nil || pageURL == nil {
		return nil
	}
	forms, cands := (FormActionInsecure{}).parse(body, pageURL)
	out := make([]FormActionCandidate, 0, len(cands))
	for _, c := range cands {
		var inputs []FormActionInput
		var hasCred bool
		if c.formIdx >= 0 && c.formIdx < len(forms) {
			for _, in := range forms[c.formIdx].inputs {
				inputs = append(inputs, FormActionInput{
					Name:      in.name,
					Type:      in.typ,
					Sensitive: in.sensitive,
				})
				if in.sensitive {
					hasCred = true
				}
			}
		}
		out = append(out, FormActionCandidate{
			Raw:                c.raw,
			Resolved:           c.resolved.String(),
			Method:             c.method,
			Override:           c.override,
			Inputs:             inputs,
			HasCredentialField: hasCred,
		})
	}
	return out
}

// SQLiErrorPayloads returns the curated PayloadSQLiError catalogue in
// the same order PayloadsFor produces it. The Lua port iterates these
// in order so its first-hit-wins behavior matches the Go check 1:1.
type SQLiErrorPayload struct {
	Name     string
	Template string
}

func SQLiErrorPayloads() []SQLiErrorPayload {
	return payloadsAsLuaShape(PayloadSQLiError)
}

// payloadsAsLuaShape returns PayloadsFor(class) re-shaped into the
// {Name, Template} pair the bridge marshals into Lua tables. Every
// caller wants the same projection (name + template, drop the class
// tag the Go side already conditioned on), so centralising it keeps
// the per-class helpers below one-liners and avoids per-call slice
// shape drift between the seven payload classes.
func payloadsAsLuaShape(class PayloadClass) []SQLiErrorPayload {
	src := PayloadsFor(class)
	out := make([]SQLiErrorPayload, 0, len(src))
	for _, p := range src {
		out = append(out, SQLiErrorPayload{Name: p.Name, Template: p.Template})
	}
	return out
}

// TraversalPayloadsLua / SQLiTimePayloadsLua / CmdInjectPayloadsLua /
// CmdInjectBlindPayloadsLua / XSSPayloadsLua mirror SQLiErrorPayloads
// for the other PayloadClass values the Lua bridge surfaces. Each is
// a one-liner so the Lua port iterates a stable list in the same order
// the Go side already produces.
func TraversalPayloadsLua() []SQLiErrorPayload      { return payloadsAsLuaShape(PayloadTraversal) }
func SQLiTimePayloadsLua() []SQLiErrorPayload       { return payloadsAsLuaShape(PayloadSQLiTime) }
func CmdInjectPayloadsLua() []SQLiErrorPayload      { return payloadsAsLuaShape(PayloadCmdInject) }
func CmdInjectBlindPayloadsLua() []SQLiErrorPayload { return payloadsAsLuaShape(PayloadCmdInjectBlind) }
func XSSPayloadsLua() []SQLiErrorPayload            { return payloadsAsLuaShape(PayloadXSS) }

// SQLiBooleanPairsLua exposes the curated boolean-pair set the Lua
// port iterates. Same projection as the underlying SQLiBooleanPairs;
// re-exported with the Lua suffix so the bridge can read every payload
// catalogue under a uniform name.
type LuaBooleanPair struct {
	Name  string
	True  string
	False string
}

func SQLiBooleanPairsLua() []LuaBooleanPair {
	src := SQLiBooleanPairs()
	out := make([]LuaBooleanPair, 0, len(src))
	for _, p := range src {
		out = append(out, LuaBooleanPair{Name: p.Name, True: p.True, False: p.False})
	}
	return out
}

// TraversalNewMarkers wraps the path-traversal check's marker-scan +
// baseline-subtraction step. body and baseline are both raw response
// bytes; the result is the TraversalMarkers entries present in body
// that did not already appear in baseline. Mirrors the SQLiErrorNewMatches
// shape used by the existing sqli-error Lua port.
func TraversalNewMarkers(body, baseline []byte) []string {
	return subtractPatterns(matchTraversalMarkers(body), matchTraversalMarkers(baseline))
}

// TraversalMarkerHits returns the un-subtracted marker hits in body.
// Exposed as a separate accessor (in addition to TraversalNewMarkers)
// so a Lua-side debug surface can show "this many markers were already
// present in baseline" without re-running the scan twice.
func TraversalMarkerHits(body []byte) []string { return matchTraversalMarkers(body) }

// PathSinkCandidate forwards pathSinkCandidate. The Lua port gates the
// sweep on the same heuristic the Go check uses so the request count
// stays identical between the two implementations.
func PathSinkCandidate(s Sink) bool { return pathSinkCandidate(s) }

// LDAPErrorNewMatches / LDAPiBooleanPairsLua / LDAPiErrorPayloadsLua
// expose the LDAPi check's private pattern + payload sets. The pattern
// catalogue and the matcher live in Go; the Lua port owns the per-sink
// orchestration only.
func LDAPErrorNewMatches(body, baseline []byte) []string {
	return subtractPatterns(matchLDAPErrors(body), matchLDAPErrors(baseline))
}

// LDAPiBooleanProbePair carries one LDAPi truthy/falsy probe pair.
// FalsyTemplate carries the {{CANARY}} placeholder the Lua port
// substitutes per probe (one fresh canary per pair) before the
// suffix gets concatenated onto sink.Value.
type LDAPiBooleanProbePair struct {
	Name          string
	Truthy        string
	FalsyTemplate string
}

func LDAPiBooleanPairsLua() []LDAPiBooleanProbePair {
	out := make([]LDAPiBooleanProbePair, 0, len(ldapiBooleanPairs))
	for _, p := range ldapiBooleanPairs {
		out = append(out, LDAPiBooleanProbePair{Name: p.Name, Truthy: p.Truthy, FalsyTemplate: p.FalsyTpl})
	}
	return out
}

// LDAPiCanaryPlaceholder exposes the placeholder string the Lua port
// substitutes per probe. Lua-side authors call this rather than
// hard-coding "{{CANARY}}" so a future change to the placeholder lands
// once, in Go.
func LDAPiCanaryPlaceholder() string { return ldapiCanaryPlaceholder }

func LDAPiErrorPayloadsLua() []string {
	out := make([]string, len(ldapiErrorPayloads))
	copy(out, ldapiErrorPayloads)
	return out
}

// LDAPiSinkProbable forwards (LDAPi).sinkProbable so the Lua port
// drops the same Loc set the Go check skips (header / cookie).
func LDAPiSinkProbable(loc string) bool { return (LDAPi{}).sinkProbable(Sink{Loc: Loc(loc)}) }

// MongoErrorNewMatches / NoSQLiBooleanOpsLua / NoSQLiErrorPayloadsLua
// expose the NoSQLi check's private pattern + operator + payload sets.
func MongoErrorNewMatches(body, baseline []byte) []string {
	return subtractPatterns(matchMongoErrors(body), matchMongoErrors(baseline))
}

// NoSQLiBooleanOperator carries one MongoDB operator the Lua port
// iterates. KeySuffix is the wire form for query / form sinks
// ("[$eq]", "[$in][0]"); the JSON-body variant is built by the Lua
// bridge's nosqli_build_operator_request helper (which dispatches on
// op_name to apply the right nested-object shape).
type NoSQLiBooleanOperator struct {
	Name      string
	KeySuffix string
}

func NoSQLiBooleanOpsLua() []NoSQLiBooleanOperator {
	out := make([]NoSQLiBooleanOperator, 0, len(nosqliBooleanOps))
	for _, op := range nosqliBooleanOps {
		out = append(out, NoSQLiBooleanOperator{Name: op.Name, KeySuffix: op.KeySuffix})
	}
	return out
}

func NoSQLiErrorPayloadsLua() []string {
	out := make([]string, len(nosqliErrorPayloads))
	copy(out, nosqliErrorPayloads)
	return out
}

// NoSQLiSinkProbable forwards (NoSQLi).sinkProbable so the Lua port
// gates on the same Loc set the Go check accepts (query / form / json).
func NoSQLiSinkProbable(loc string) bool { return (NoSQLi{}).sinkProbable(Sink{Loc: Loc(loc)}) }

// NoSQLiBuildOperatorRequest builds an *http.Request that applies the
// named operator (op_name = "eq" / "in-array") to sink with opValue.
// Wraps the package-private buildOperatorRequest so the Lua port can
// produce the wire-shape rewrites (bracket key for query / form,
// nested JSON for body) without re-implementing the per-loc shape rules.
func NoSQLiBuildOperatorRequest(ctx context.Context, sink Sink, opName, opValue string) (*http.Request, error) {
	var op *nosqliOp
	for i := range nosqliBooleanOps {
		if nosqliBooleanOps[i].Name == opName {
			op = &nosqliBooleanOps[i]
			break
		}
	}
	if op == nil {
		return nil, fmt.Errorf("nosqli: unknown operator %q", opName)
	}
	return (NoSQLi{}).buildOperatorRequest(ctx, sink, *op, opValue)
}

// CmdErrorFirstMatch returns the first cmd-error pattern that appears
// in body, or "" when none does. Wraps the same case-insensitive scan
// the Go check uses inline so the Lua port consumes the result without
// re-shaping the catalogue.
func CmdErrorFirstMatch(body []byte) string {
	lower := strings.ToLower(string(body))
	for _, sig := range CmdErrorPatterns() {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}

// SSTIErrorNewMatches / SSTIErrorPayloadsLua / SSTIConfirmProbeLua
// expose the SSTI check's pattern catalogue, error-payload list, and
// confirm-probe deriver.
func SSTIErrorNewMatches(body, baseline []byte) []string {
	return subtractPatterns(matchSSTIErrors(body), matchSSTIErrors(baseline))
}

func SSTIErrorPayloadsLua() []string {
	out := make([]string, len(sstiErrorPayloads))
	copy(out, sstiErrorPayloads)
	return out
}

// SSTIConfirmProbeLua returns the (template, expected) pair derived
// from the original probe by swapping the "7*7"/"49" operands for
// "8*9"/"72". A genuine SSTI evaluates the second probe in the same
// engine syntax; a passively-reflecting page cannot replay a fresh
// expression. Mirrors SSTI.confirmProbe verbatim.
func SSTIConfirmProbeLua(template string) (string, string) {
	return strings.Replace(template, "7*7", "8*9", 1), "72"
}

// XSSPayloadsForContextsLua exposes payloadsForContexts so the Lua
// reflected-xss port picks the same context-matched payload subset
// (deduped, source-ordered) the Go check uses. Reflections arrive as
// the context-string slice the bridge already exposes via FindReflections.
func XSSPayloadsForContextsLua(contexts []string, level string) []SQLiErrorPayload {
	parsedLevel, err := ParseLevel(level)
	if err != nil {
		parsedLevel = LevelDefault
	}
	refs := make([]Reflection, 0, len(contexts))
	for _, name := range contexts {
		refs = append(refs, Reflection{Context: contextFromString(name)})
	}
	picked := payloadsForContexts(refs, parsedLevel)
	out := make([]SQLiErrorPayload, 0, len(picked))
	for _, p := range picked {
		out = append(out, SQLiErrorPayload{Name: p.Name, Template: p.Template})
	}
	return out
}

// XSSContextSummaryLua returns the comma-separated, dedup-ordered list
// of context names from contexts. Mirrors contextSummary.
func XSSContextSummaryLua(contexts []string) string {
	refs := make([]Reflection, 0, len(contexts))
	for _, name := range contexts {
		refs = append(refs, Reflection{Context: contextFromString(name)})
	}
	return contextSummary(refs)
}

// contextFromString is the inverse of Context.String. Used by the Lua
// bridge to round-trip context strings back into the typed enum so the
// payload selector + summary functions get the same values FindReflections
// produced.
func contextFromString(name string) Context {
	switch name {
	case "header-value":
		return CtxHeaderValue
	case "html-text":
		return CtxHTMLText
	case "html-comment":
		return CtxHTMLComment
	case "attr-double-quoted":
		return CtxAttrDoubleQuoted
	case "attr-single-quoted":
		return CtxAttrSingleQuoted
	case "attr-unquoted":
		return CtxAttrUnquoted
	case "script-text":
		return CtxScriptText
	case "script-string-double":
		return CtxScriptStringDouble
	case "script-string-single":
		return CtxScriptStringSingle
	}
	return CtxNone
}

// FindReflectionsLua wraps FindReflections so the Lua bridge returns
// a flat array of {context, offset, header} tables. The typed Go API
// returns []Reflection; the Lua shape uses the context's string name
// so the comparator on the Lua side matches the constants the user
// already sees.
type LuaReflection struct {
	Context string
	Offset  int
	Header  string
}

func FindReflectionsLua(body []byte, headers http.Header, token string) []LuaReflection {
	src := FindReflections(body, headers, token)
	out := make([]LuaReflection, 0, len(src))
	for _, r := range src {
		out = append(out, LuaReflection{Context: r.Context.String(), Offset: r.Offset, Header: r.Header})
	}
	return out
}

// CachePoisonHeaderProbeLua is one unkeyed-header probe the cache-
// poisoning Lua port sends. Header / Value are the wire pair; Canary
// is what the reflection check searches for in the response; Kind
// flags whether the probe should also consult responseDiverged
// (path-rewrite primitives) on top of the reflection check.
// DeceptionMessage is the human-facing detail lead-in.
type CachePoisonHeaderProbeLua struct {
	Header           string
	Value            string
	Canary           string
	Kind             string
	DeceptionMessage string
}

// CachePoisonHeaderProbesLua exposes the curated probe list. Mirrors
// the Go check's cachePoisonHeaderProbes() one-for-one so the Lua port
// runs the same probes in the same order.
func CachePoisonHeaderProbesLua() []CachePoisonHeaderProbeLua {
	return []CachePoisonHeaderProbeLua{
		{
			Header:           "X-Forwarded-Host",
			Value:            cachePoisonCanaryHost,
			Canary:           cachePoisonCanaryHost,
			Kind:             "reflection",
			DeceptionMessage: "Back-end echoes X-Forwarded-Host into the response body or absolute URLs without keying the cache on it.",
		},
		{
			Header:           "X-Forwarded-Scheme",
			Value:            "nothttps",
			Canary:           "nothttps://",
			Kind:             "reflection",
			DeceptionMessage: "Back-end rewrites generated absolute URLs to use the attacker-supplied scheme (X-Forwarded-Scheme).",
		},
		{
			Header:           "X-Forwarded-Proto",
			Value:            "nothttps",
			Canary:           "nothttps://",
			Kind:             "reflection",
			DeceptionMessage: "Back-end rewrites generated absolute URLs to use the attacker-supplied scheme (X-Forwarded-Proto).",
		},
		{
			Header:           "X-Original-URL",
			Value:            cachePoisonCanaryPath,
			Canary:           cachePoisonCanaryPath,
			Kind:             "reflection-or-diverged",
			DeceptionMessage: "Back-end honours X-Original-URL to override the routed path without rechecking authorization.",
		},
		{
			Header:           "X-Rewrite-URL",
			Value:            cachePoisonCanaryPath,
			Canary:           cachePoisonCanaryPath,
			Kind:             "reflection-or-diverged",
			DeceptionMessage: "Back-end honours X-Rewrite-URL to override the routed path without rechecking authorization.",
		},
	}
}

// CachePoisonHasCacheHint forwards hasCacheHint so the Lua port short-
// circuits the unkeyed-header arm on pages whose baseline response
// carries no cache hint (Cache-Control, Age, X-Cache, CF-Cache-Status,
// Via). Without a shared cache in the path the worst case is local
// reflection; gating prevents the noisy probe from firing on a target
// the bug class does not apply to.
func CachePoisonHasCacheHint(h http.Header) bool { return cacheHintsPresent(h) }

// CachePoisonFindReflection wraps findReflection so the Lua port can
// run the same body + header lookup the Go check uses. needle is the
// canary string; resp + body are the probe response; baseBody is the
// baseline body bytes (used to drop pre-existing echoes). Returns the
// location string ("response body", "Location header", "") and a bool.
func CachePoisonFindReflection(needle string, headers http.Header, body, baseBody []byte) (string, bool) {
	lowerNeedle := strings.ToLower(needle)
	if needle == "" {
		return "", false
	}
	if len(baseBody) > 0 && strings.Contains(strings.ToLower(string(baseBody)), lowerNeedle) {
		return "", false
	}
	if len(body) > 0 && strings.Contains(strings.ToLower(string(body)), lowerNeedle) {
		return "response body", true
	}
	for _, h := range []string{"Location", "Link", "Set-Cookie", "Content-Location", "Refresh"} {
		for _, v := range headers.Values(h) {
			if strings.Contains(strings.ToLower(v), lowerNeedle) {
				return h + " header", true
			}
		}
	}
	return "", false
}

// CachePoisonResponseDiverged wraps responseDiverged. status / body are
// the probe response shape; baseStatus / baseBody are the baseline. Used
// by the path-rewrite probes (X-Original-URL / X-Rewrite-URL) where the
// canary path itself rarely echoes back; instead the signal is "the
// response looks like a different page".
func CachePoisonResponseDiverged(status int, body []byte, baseStatus int, baseBody []byte) bool {
	if status != baseStatus {
		return true
	}
	if len(body) == 0 || len(baseBody) == 0 {
		return false
	}
	a, b := len(body), len(baseBody)
	if a < b {
		a, b = b, a
	}
	if a-b > a/4 {
		return true
	}
	return false
}

// CachePoisonBodiesMatch wraps bodiesMatch for the cache-deception arm.
// The two snapshots are the deception-probe body vs. the baseline body;
// returns true when they look like the same authenticated page modulo
// rotating tokens.
func CachePoisonBodiesMatch(deceived, baseline []byte) bool {
	return bodiesMatch(deceived, baseline)
}

// CachePoisonCacheControlForbidsStorage forwards the Cache-Control
// "no-store" / "private" detector. The deception arm uses this to
// downgrade severity from High to Medium when the upstream explicitly
// forbids storage.
func CachePoisonCacheControlForbidsStorage(cc string) bool { return cacheControlForbidsStorage(cc) }

// CachePoisonIsAuthLikelyPath forwards the per-path heuristic the cache-
// deception arm uses to gate the probe at LevelDefault.
func CachePoisonIsAuthLikelyPath(path string) bool { return isAuthLikelyPath(path) }

// CachePoisonDeceptionURL forwards deceptionURL. raw is the absolute
// target URL; the result is target with cacheDeceptionSuffix appended
// to its path (or "" when the target already ends with the suffix).
func CachePoisonDeceptionURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return deceptionURL(u)
}

// CachePoisonParseVary returns the lowercased Vary header set. The
// Lua port uses this to check whether a header is keyed before
// emitting an unkeyed-header finding.
func CachePoisonParseVary(v string) []string {
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

// CachePoisonDeceptionSuffix exposes the static-asset suffix the cache-
// deception arm appends to a probe URL. Centralised so the Go and Lua
// checks agree on the wire shape; a change to "what does a cache-
// rule trigger on" lands once.
func CachePoisonDeceptionSuffix() string { return cacheDeceptionSuffix }

// CachePoisonProbeURL forwards cachePoisonProbeURL so the Lua port
// builds unkeyed-header probe URLs through the same random-
// cachebuster pipeline the Go check uses. Both implementations MUST
// route every probe through this helper; firing at the canonical
// (method, path, query) instead would mean the probe response a
// vulnerable cache stores lands on the exact key real victims hit.
func CachePoisonProbeURL(target string) (string, error) { return cachePoisonProbeURL(target) }

// CachePoisonCachebusterParam exposes the cachebuster query name so a
// parity test can assert both implementations append it and never hit
// the canonical URL bare.
func CachePoisonCachebusterParam() string { return cachePoisonCachebusterParam }

// CachePoisonCanaryHost / CachePoisonCanaryPath expose the canary
// values the Lua port stamps onto evidence + dedupe keys. Mirrors
// the Go check constants 1:1.
func CachePoisonCanaryHost() string { return cachePoisonCanaryHost }
func CachePoisonCanaryPath() string { return cachePoisonCanaryPath }

// SQLiTimeSleepSeconds / SQLiTimeMargin expose the Go side's test-
// tunable timing knobs to the Lua port. Lua checks read these every
// Run so a test that calls SetSQLiTimeSleepForTest (in the Go test
// helper file) flips both implementations to the same fast value
// without each side hand-rolling its own override path.
func SQLiTimeSleepSeconds() int { return int(sqliTimeSleep / 1e9) }
func SQLiTimeMargin() float64   { return sqliTimeMargin }

// CmdInjectionSleepSeconds / CmdInjectionMargin do the same for the
// cmd-injection timing oracle. Same rationale: tests flip the Go side
// and the Lua port follows in lockstep.
func CmdInjectionSleepSeconds() int { return int(cmdInjectionSleep / 1e9) }
func CmdInjectionMargin() float64   { return cmdInjectionMargin }

// SetSQLiTimeTuningForTest / SetCmdInjectionTuningForTest let the
// checks_lua parity tests dial the production timing knobs down to
// test-friendly values without each test reaching into private vars.
// Mirrors the SubdomainTakeoverLookup setters below.
func SetSQLiTimeTuningForTest(sleepSecs int, margin float64) (restore func()) {
	prevSleep, prevMargin := sqliTimeSleep, sqliTimeMargin
	sqliTimeSleep = time.Duration(sleepSecs) * time.Second
	sqliTimeMargin = margin
	return func() {
		sqliTimeSleep = prevSleep
		sqliTimeMargin = prevMargin
	}
}
func SetCmdInjectionTuningForTest(sleepSecs int, margin float64) (restore func()) {
	prevSleep, prevMargin := cmdInjectionSleep, cmdInjectionMargin
	cmdInjectionSleep = time.Duration(sleepSecs) * time.Second
	cmdInjectionMargin = margin
	return func() {
		cmdInjectionSleep = prevSleep
		cmdInjectionMargin = prevMargin
	}
}

// CmdInjectionFillerValue exposes the filler the cmd-injection checks
// substitute for an empty sink.Value before payload append. Empty
// originals leave the payload without a leading character; anchoring
// with "1" turns `param=` into `param=1; sleep 5`, which executes.
func CmdInjectionFillerValue() string { return cmdInjectionFillerValue }

// CmdInjectionBlindOOBPayloadLua / CmdInjectionBlindOOBPayloadsLua
// expose the OOB-only payload list for the cmd-injection-blind check.
// Each entry is one canary-fetching shell-context template; the Lua
// port substitutes {{URL}} per probe with the canary URL the OOB
// listener minted.
type CmdInjectionBlindOOBPayloadLua struct {
	Name     string
	Template string
}

func CmdInjectionBlindOOBPayloadsLua() []CmdInjectionBlindOOBPayloadLua {
	out := make([]CmdInjectionBlindOOBPayloadLua, 0, len(cmdInjectionBlindOOBPayloads))
	for _, p := range cmdInjectionBlindOOBPayloads {
		out = append(out, CmdInjectionBlindOOBPayloadLua{Name: p.Name, Template: p.Tmpl})
	}
	return out
}

// SSTIOOBPayloadLua / SSTIOOBPayloadsLua mirror the cmd-injection-blind
// pair for SSTI. Each entry is one engine-specific blind probe; the
// Lua port substitutes {{URL}} with the canary URL on send. Engine
// rides as a field so the Drain pass can attribute the right engine
// name on a confirmed callback.
type SSTIOOBPayloadLua struct {
	Engine   string
	Template string
}

func SSTIOOBPayloadsLua() []SSTIOOBPayloadLua {
	out := make([]SSTIOOBPayloadLua, 0, len(sstiOOBPayloads))
	for _, p := range sstiOOBPayloads {
		out = append(out, SSTIOOBPayloadLua{Engine: p.Engine, Template: p.Tmpl})
	}
	return out
}

// LocDescriptorLua forwards the locDescriptor helper so the Lua port
// renders titles like "header" / "cookie" / "parameter" the same way
// the Go check does. Drops the need for a per-port lookup table.
func LocDescriptorLua(loc string) string { return locDescriptor(Loc(loc)) }

// SubdomainTakeoverLookupCNAMEForTest / SetSubdomainTakeoverLookupCNAMEForTest
// expose the package-level CNAME resolver indirection so the
// checks_lua parity tests can swap in a synthetic resolver without
// reaching into private state. The Go-side check_test.go uses the
// private var directly; the Lua-side parity tests live in a different
// package and must use these wrappers.
func SubdomainTakeoverLookupCNAMEForTest() func(ctx context.Context, host string) (string, error) {
	return subdomainTakeoverLookupCNAME
}
func SetSubdomainTakeoverLookupCNAMEForTest(fn func(ctx context.Context, host string) (string, error)) {
	subdomainTakeoverLookupCNAME = fn
}

// SubdomainTakeoverLookupHostForTest / SetSubdomainTakeoverLookupHostForTest
// expose the package-level host-resolver indirection for the same
// reason as the CNAME pair above.
func SubdomainTakeoverLookupHostForTest() func(ctx context.Context, host string) ([]string, error) {
	return subdomainTakeoverLookupHost
}
func SetSubdomainTakeoverLookupHostForTest(fn func(ctx context.Context, host string) ([]string, error)) {
	subdomainTakeoverLookupHost = fn
}

// SSRFCanaryLua / SSRFBodyCapLua / SSRFSpecificParamNamesLua /
// SSRFGenericParamNamesLua / SSRFLooksProxyish / SSRFMatchesError are
// the algorithm inputs and pattern matcher the Lua port of the SSRF
// check reads. The canary URL, body cap, parameter-name catalogues
// (specific vs generic), proxy-ish path keywords, and error-signature
// table all stay in Go so a future tightening lands once; the rule's
// finding catalog (title / severity / detail / dedupe key) is composed
// in ssrf.lua.
func SSRFCanaryLua() string { return ssrfCanary }

func SSRFBodyCapLua() int { return ssrfBodyCap }

func SSRFSpecificParamNamesLua() []string {
	out := make([]string, len(ssrfSpecificParamNames))
	copy(out, ssrfSpecificParamNames)
	return out
}

func SSRFGenericParamNamesLua() []string {
	out := make([]string, len(ssrfGenericParamNames))
	copy(out, ssrfGenericParamNames)
	return out
}

func SSRFLooksProxyish(path string) bool { return looksProxyish(path) }

func SSRFMatchesError(body []byte) string { return ssrfMatchesError(body) }

// DeserialFormatLua names one server-side deserialization format the
// insecure-deserialization Lua port surfaces. Same shape across the
// passive (fingerprint) and active (probe) arms so the .lua file can
// iterate one catalogue and route by Name when it builds findings.
type DeserialFormatLua struct {
	Name         string
	Label        string
	ProbePayload string
	ErrorPats    []string
}

// DeserialFormatListLua returns the named catalogue's format list
// translated into the Lua-bridge shape. "http_body" covers the seven
// HTTP-body deserialization formats this package has always shipped
// (Java, .NET, pickle, Ruby Marshal, PHP, node-serialize, YAML);
// unknown / empty catalogue names fall back to "http_body" via
// resolveDeserialCatalogue. The .lua port reads the list once per
// Run and uses Name to route between the per-format probe / match
// helpers.
func DeserialFormatListLua(catalogue string) []DeserialFormatLua {
	cat := resolveDeserialCatalogue(catalogue)
	out := make([]DeserialFormatLua, 0, len(cat.formats))
	for _, f := range cat.formats {
		pats := make([]string, len(f.errorPats))
		copy(pats, f.errorPats)
		out = append(out, DeserialFormatLua{
			Name:         f.name,
			Label:        f.label,
			ProbePayload: f.probePayload,
			ErrorPats:    pats,
		})
	}
	return out
}

// DeserialClassifyValueLua returns the (name, label) of the first
// format in the named catalogue whose fingerprint matches s, or
// ("", "") when no format matched. Wraps the Go check's
// classifyDeserial so the passive arm of the .lua port runs the same
// detection over cookie / query / form-input values.
func DeserialClassifyValueLua(catalogue, s string) (string, string) {
	fp := classifyDeserial(s, resolveDeserialCatalogue(catalogue))
	if fp == nil {
		return "", ""
	}
	return fp.name, fp.label
}

// DeserialMatchAllLua returns the union of error patterns across
// every format in the named catalogue that appear in body. The .lua
// port uses this to build the baseline pattern set so per-format
// probes can subtract what was already present.
func DeserialMatchAllLua(catalogue string, body []byte) []string {
	return matchDeserialAll(body, resolveDeserialCatalogue(catalogue))
}

// DeserialMatchFormatLua returns the subset of formatName's error
// patterns present in body. catalogue selects the format set
// formatName is looked up in (e.g. "http_body"); formatName is the
// name slug exposed by DeserialFormatListLua (e.g. "java", "dotnet").
func DeserialMatchFormatLua(catalogue string, body []byte, formatName string) []string {
	cat := resolveDeserialCatalogue(catalogue)
	for _, f := range cat.formats {
		if f.name == formatName {
			return matchDeserialFormat(body, f)
		}
	}
	return nil
}

// DeserialBodyMarkerLua returns the human-readable label of the first
// deserialization fingerprint visible in body, or "" when none.
// Catalogue-independent: the marker set is a fixed list of base64 /
// text prefixes hardcoded in bodyDeserialMarker rather than read from
// the format catalogue.
func DeserialBodyMarkerLua(body []byte) string {
	return bodyDeserialMarker(body)
}

// IsEventStreamContentType reports whether ct names a Server-Sent
// Events stream. Parameters (charset, boundary) are stripped before
// comparison so a perfectly labeled response is not skipped on a
// technicality. Mirrors isEventStream so the Lua port and the
// Go original gate on the same content-type rule.
func IsEventStreamContentType(ct string) bool { return isEventStream(ct) }

// FindEventSourceLiteralsLua scans body for `new EventSource(...)`
// constructions and returns the URL captures in document order
// (duplicates preserved; the caller dedupes after resolving against a
// base URL). Bounded scan: only the first sseBodyCap bytes are
// inspected, matching the Go check.
func FindEventSourceLiteralsLua(body []byte) []string {
	if len(body) > sseBodyCap {
		body = body[:sseBodyCap]
	}
	matches := sseEventSourceRE.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 2 {
			out = append(out, string(m[1]))
		}
	}
	return out
}

// OpenAPIExampleAuthMatchLua is one Bearer/Basic value found in an
// example / default / value block of an OpenAPI spec body. The scheme
// is normalized to title-case ("Bearer" / "Basic"); raw is the value
// portion as it appears in the source; redacted is the safe-to-render
// version composed with the shared RedactSecret helper.
type OpenAPIExampleAuthMatchLua struct {
	Scheme   string
	Raw      string
	Redacted string
}

// ProtoPollutionIsJSONResponse wraps isJSONResponse so the Lua port
// applies the same content-type + body-start sniffing the Go check
// uses to decide whether the json-spaces gadget applies.
func ProtoPollutionIsJSONResponse(ct string, body []byte) bool {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return isJSONResponse(h, body)
}

// ProtoPollutionJSONIndentWidth wraps jsonIndentWidth so the Lua port
// reads the indent-GCD the same way the Go check does. Returns 0 when
// no indented JSON lines are present, 1 when mixed indents collapse,
// otherwise the GCD of every observed indent run.
func ProtoPollutionJSONIndentWidth(body []byte) int {
	return jsonIndentWidth(body)
}

// XXEErrorPatternsLua returns every xxe parser-error pattern present
// in body. Lowercases body once inside the helper - matches the Go
// check's case-insensitive substring scan. The .lua port uses this
// for baseline + payload-stage subtraction.
func XXEErrorPatternsLua(body []byte) []string {
	return matchXXEErrors(body)
}

// XXEBase64MarkersLua returns every php-filter base64 marker present
// in body. Case-sensitive (base64 alphabet) to avoid collisions with
// prose.
func XXEBase64MarkersLua(body []byte) []string {
	return matchXXEBase64Markers(body)
}

// XXEFileDiscloseDocsLua exposes the file-disclosure XML payloads in
// the order the Go check sweeps them. The .lua port iterates this
// list verbatim so the wire shapes stay a single source of truth.
func XXEFileDiscloseDocsLua() []string {
	out := make([]string, len(xxeFileDiscloseDocs))
	copy(out, xxeFileDiscloseDocs)
	return out
}

// XXEErrorDocsLua exposes the error-based XML payloads, same shape as
// XXEFileDiscloseDocsLua.
func XXEErrorDocsLua() []string {
	out := make([]string, len(xxeErrorDocs))
	copy(out, xxeErrorDocs)
	return out
}

// XXEBaselineDocLua returns the benign XML body the .lua port sends
// once per candidate to gather baseline markers / errors. Keeping the
// literal in one place ensures the byte-for-byte baseline matches
// across Go and Lua.
func XXEBaselineDocLua() string { return xxeBaselineDoc }

// XXEExtractSystemTargetLua wraps extractSystemTarget so the .lua port
// names the requested file in finding detail without re-implementing
// the SYSTEM-attribute parser.
func XXEExtractSystemTargetLua(doc string) string {
	return extractSystemTarget(doc)
}

// XXEExtractExfilDataLua wraps extractExfilData so the DTD-exfil drain
// path on the .lua side recovers the disclosed payload from the exfil
// callback path.
func XXEExtractExfilDataLua(rawPath string) string {
	return extractExfilData(rawPath)
}

// XXEOOBExfilProbeFileLua returns the file the OOB DTD-exfil DTD reads
// (file:///etc/hostname). The .lua port embeds it in finding text so
// readers know what the chain attempted to disclose.
func XXEOOBExfilProbeFileLua() string { return xxeOOBExfilProbeFile }

// ContentDiscoveryEntryLua is one wordlist entry surfaced to the Lua
// content-discovery port. Mirrors discoveryEntry verbatim - the .lua
// port reads these fields and composes finding text from them.
type ContentDiscoveryEntryLua struct {
	Path                 string
	Severity             string
	Title                string
	Detail               string
	CWE                  string
	OWASP                string
	Remediation          string
	Marker               string
	ExpectedContentTypes []string
	Emit                 bool
}

// ContentDiscoveryEntriesLua returns the wordlist entries the main
// sweep should probe against hostname, filtered by aggressive level
// and stack constraint. Host-named backup synthetics (when the
// catalogue defines a generator) are appended in the order the Go
// check produces. Returning a flat slice keeps the .lua iteration
// shape simple.
//
// catalogue selects which registered wordlist to walk; pass "common"
// for the canonical content-discovery list, or any name a future
// sibling catalogue is registered under. Unknown / empty names fall
// back to "common" so a Lua-side typo doesn't silently turn into a
// no-op sweep.
func ContentDiscoveryEntriesLua(catalogue string, aggressive bool, hostname string, stack *fingerprint.Stack) []ContentDiscoveryEntryLua {
	cat := resolveDiscoveryCatalogue(catalogue)
	out := make([]ContentDiscoveryEntryLua, 0, len(cat.entries)+8)
	for _, e := range cat.entries {
		if e.Aggressive && !aggressive {
			continue
		}
		if !e.appliesTo(stack) {
			continue
		}
		out = append(out, toContentDiscoveryEntryLua(e))
	}
	if cat.hostBackup != nil {
		for _, e := range cat.hostBackup(hostname) {
			out = append(out, toContentDiscoveryEntryLua(e))
		}
	}
	return out
}

// ContentDiscoveryFollowUpsLua returns the second-wave entries to
// probe given the set of paths whose first-wave probes fired and the
// set already probed. catalogue picks which registered follow-up
// group set to evaluate, mirroring ContentDiscoveryEntriesLua's
// resolution rule.
func ContentDiscoveryFollowUpsLua(catalogue string, hits map[string]struct{}, probed map[string]struct{}, stack *fingerprint.Stack) []ContentDiscoveryEntryLua {
	if len(hits) == 0 {
		return nil
	}
	cat := resolveDiscoveryCatalogue(catalogue)
	var out []ContentDiscoveryEntryLua
	queued := map[string]struct{}{}
	for _, g := range cat.followUps {
		triggered := false
		for _, t := range g.Triggers {
			if _, ok := hits[t]; ok {
				triggered = true
				break
			}
		}
		if !triggered {
			continue
		}
		for _, e := range g.Entries {
			if _, dup := probed[e.Path]; dup {
				continue
			}
			if _, dup := queued[e.Path]; dup {
				continue
			}
			if !e.appliesTo(stack) {
				continue
			}
			queued[e.Path] = struct{}{}
			out = append(out, toContentDiscoveryEntryLua(e))
		}
	}
	return out
}

func toContentDiscoveryEntryLua(e discoveryEntry) ContentDiscoveryEntryLua {
	cts := make([]string, len(e.ExpectedContentTypes))
	copy(cts, e.ExpectedContentTypes)
	return ContentDiscoveryEntryLua{
		Path:                 e.Path,
		Severity:             string(e.Severity),
		Title:                e.Title,
		Detail:               e.Detail,
		CWE:                  e.CWE,
		OWASP:                e.OWASP,
		Remediation:          e.Remediation,
		Marker:               e.Marker,
		ExpectedContentTypes: cts,
		Emit:                 e.Emit,
	}
}

// ContentDiscoveryBodyHashPrefixLua wraps bodyHashPrefix so the .lua
// port uses the exact same SHA1[:8] prefix the Go check uses for
// soft-404 fingerprinting.
func ContentDiscoveryBodyHashPrefixLua(body []byte) string {
	return bodyHashPrefix(body)
}

// ContentDiscoveryContentTypeFamilyLua exposes contentTypeFamily so
// the soft-404 baseline match runs on the same stripped family form
// on both sides.
func ContentDiscoveryContentTypeFamilyLua(ct string) string {
	return contentTypeFamily(ct)
}

// ContentDiscoveryContentTypeFamilyAllowedLua exposes
// contentTypeFamilyAllowed so the markerless-entry filter behaves
// identically.
func ContentDiscoveryContentTypeFamilyAllowedLua(ct string, allowed []string) bool {
	return contentTypeFamilyAllowed(ct, allowed)
}

// ContentDiscoveryLengthCloseToLua wraps lengthCloseTo so the soft-404
// length-proximity rule is single-sourced.
func ContentDiscoveryLengthCloseToLua(a, b int) bool {
	return lengthCloseTo(a, b)
}

// ContentDiscoveryCanaryPathLua mints a fresh canary suffix the .lua
// baseline probes. Two random twin halves + ".bad" matches the Go
// check's NewCanary()-NewCanary().bad shape so any host-side
// dictionary lookup behaves the same way.
func ContentDiscoveryCanaryPathLua() string {
	return "/" + NewCanary() + "-" + NewCanary() + ".bad"
}

// ContentDiscoveryBaselineProbes returns the canary probe count the
// .lua baseline issues per host. Mirrors contentDiscoveryBaselineProbes.
func ContentDiscoveryBaselineProbes() int { return contentDiscoveryBaselineProbes }

// ContentDiscoveryBodyCap returns the per-probe body-read cap.
func ContentDiscoveryBodyCap() int { return contentDiscoveryBodyCap }

// OpenAPIScanExampleAuthMatches walks body for `Bearer <token>` and
// `Basic <base64>` shapes that sit next to an OpenAPI example /
// default / value key, returning the matches in document order. The
// regex + nearby-context filter live in Go because gopher-lua's
// pattern library cannot express the lookbehind window; the Lua port
// owns deduplication / sorting / severity composition.
func OpenAPIScanExampleAuthMatches(body []byte) []OpenAPIExampleAuthMatchLua {
	matches := openAPIExampleHeaderRe.FindAllSubmatchIndex(body, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]OpenAPIExampleAuthMatchLua, 0, len(matches))
	for _, m := range matches {
		if !hasNearbyContext(body, m[0], m[1], openAPIExampleContextRe) {
			continue
		}
		scheme := titleAuthScheme(string(body[m[2]:m[3]]))
		raw := string(body[m[4]:m[5]])
		out = append(out, OpenAPIExampleAuthMatchLua{
			Scheme:   scheme,
			Raw:      raw,
			Redacted: redactSecret(raw),
		})
	}
	return out
}

// OpenAPISecurityFactsLua is the security-relevant subset of an
// OpenAPI / Swagger document the Lua authless-operations audit
// consumes. The bridge surfaces just these fields so the Lua port
// does not need to materialize the entire spec as a Lua table - a
// 4 MiB spec with hundreds of schemas would otherwise force the VM
// to allocate millions of nested table nodes for four fields it
// actually reads.
type OpenAPISecurityFactsLua struct {
	DeclaresSecurity bool
	GlobalRequired   bool
	Operations       []OpenAPISecurityOperationLua
}

// OpenAPISecurityOperationLua is one operation extracted from the
// spec's paths map. HasSecurity reports whether the operation
// carries a `security:` key at all (the marker the Lua side uses to
// distinguish "inherit global" from "override global"); Required
// reports whether that key, if present, demands authentication.
// Required is meaningless when HasSecurity is false.
type OpenAPISecurityOperationLua struct {
	Method      string
	Path        string
	HasSecurity bool
	Required    bool
}

// OpenAPIScanSecurityFacts parses body as an OpenAPI / Swagger JSON
// document via the narrow openAPISecurityDoc struct (so encoding/json
// allocates only the security-relevant subset) and returns the
// fields the .lua port needs to decide which operations are
// authless. Returns nil for bodies that aren't a JSON object or that
// fail to parse - mirrors the Go check's per-pass JSON gate. The
// audit policy (which ops to flag, dedupe / title / severity
// composition) stays in Lua.
func OpenAPIScanSecurityFacts(body []byte) *OpenAPISecurityFactsLua {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var doc openAPISecurityDoc
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil
	}
	out := &OpenAPISecurityFactsLua{
		DeclaresSecurity: doc.declaresSecurity(),
		GlobalRequired:   requirementIsAuthenticated(doc.Security),
	}
	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/") {
			continue
		}
		for _, mo := range item.methods() {
			entry := OpenAPISecurityOperationLua{
				Method: mo.method,
				Path:   path,
			}
			if mo.op.Security != nil {
				entry.HasSecurity = true
				entry.Required = requirementIsAuthenticated(*mo.op.Security)
			}
			out.Operations = append(out.Operations, entry)
		}
	}
	return out
}
