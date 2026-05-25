package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
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
			detail: fmt.Sprintf("Response carries %d Content-Security-Policy headers. Browsers intersect them, so the effective policy is the most restrictive of all directives across the headers - which is rarely what authors intend and tends to mask which directive is doing the blocking. Consolidate to a single CSP header.", len(enforcing)),
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
	src := PayloadsFor(PayloadSQLiError)
	out := make([]SQLiErrorPayload, 0, len(src))
	for _, p := range src {
		out = append(out, SQLiErrorPayload{Name: p.Name, Template: p.Template})
	}
	return out
}

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
