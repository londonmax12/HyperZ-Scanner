package checks

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// SourceMapExposure detects publicly-served JavaScript / CSS source maps.
// A source map carries the pre-minified original: file paths (often
// leaking the project's internal directory layout and naming intent),
// comments, full variable names, and not-uncommonly literals the
// minifier preserved verbatim - build-time API endpoints, internal
// hostnames, and the occasional credential. None of that is meant to
// reach the public web.
//
// Detection chains two signals so the check stays high-confidence:
//
//  1. A JS or CSS response advertises a source map. Acceptable forms:
//     - a SourceMap / X-SourceMap / X-Source-Map response header, or
//     - a trailing `//# sourceMappingURL=` (JS) / `/*# sourceMappingURL= */`
//     (CSS) comment near the end of the body. The legacy `//@` /
//     `/*@` variants emitted by older bundlers are also recognized.
//
//  2. The referenced URL fetches successfully AND the body parses as a
//     Source Map document ("version" + "sources"/"mappings" JSON keys).
//     A `data:` URI counts as confirmed exposure without a follow-up
//     fetch: the map is already embedded in the bundle every visitor
//     downloads.
//
// Signal #1 alone (a comment pointing at a 404'd map) is intentionally
// suppressed: a stale reference is not exposure, and surfacing it would
// dilute the report.
type SourceMapExposure struct{}

func (SourceMapExposure) Name() string { return "source-map-exposure" }

func (SourceMapExposure) Level() Level { return LevelPassive }

const (
	// sourceMapBodyCap bounds the host JS / CSS body we inspect. The
	// sourceMappingURL marker lives near the end of the file; 4 MiB
	// covers heavy SPA bundles without letting a misbehaving server
	// pin the worker on a long stream.
	sourceMapBodyCap = 4 << 20

	// sourceMapTail is how many trailing bytes of the host body we scan
	// for the comment marker. Bundlers always emit it on the last line;
	// 4 KiB is a generous overestimate that tolerates a license footer
	// or post-build banner pushed in after the bundler ran.
	sourceMapTail = 4 << 10

	// sourceMapProbeBodyCap bounds the body of the verification GET.
	// We only need the leading JSON keys to confirm Source Map shape;
	// 64 KiB clears that header even on large bundles.
	sourceMapProbeBodyCap = 64 << 10
)

// JS form: //# sourceMappingURL=<url>  (also //@ on legacy bundlers)
// CSS form: /*# sourceMappingURL=<url> */ (also /*@)
//
// The comment must sit on its own line in JS; CSS allows it inline so
// the regex doesn't anchor to line boundaries. The URL capture stops at
// the first whitespace, which keeps `*/` in the CSS form outside the
// match.
var (
	sourceMapJSCommentRE  = regexp.MustCompile(`(?m)^[ \t]*//[#@][ \t]+sourceMappingURL[ \t]*=[ \t]*(\S+)[ \t]*$`)
	sourceMapCSSCommentRE = regexp.MustCompile(`/\*[#@][ \t]+sourceMappingURL[ \t]*=[ \t]*(\S+)[ \t]*\*/`)

	// Source Map v3 anchors. The spec mandates "version":3 but real-world
	// tooling has shipped 1/2/3 over the years; accept any integer and
	// rely on the "sources" or "mappings" key to confirm shape. Without
	// either of those, an arbitrary JSON document carrying a "version"
	// field would false-positive.
	sourceMapVersionRE  = regexp.MustCompile(`"version"\s*:\s*\d+`)
	sourceMapSourcesRE  = regexp.MustCompile(`"sources"\s*:\s*\[`)
	sourceMapMappingsRE = regexp.MustCompile(`"mappings"\s*:\s*"`)
)

func (c SourceMapExposure) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, sourceMapBodyCap)
	if err != nil {
		return nil, err
	}
	kind, ok := sourceMappableKind(snap.Headers.Get("Content-Type"))
	if !ok {
		return nil, nil
	}

	ref := findSourceMapReference(snap.Headers, snap.Body, kind)
	if ref == "" {
		return nil, nil
	}

	// Inline (data:) map: the .map content is embedded in the bundle we
	// already served. No follow-up fetch can add information; the
	// exposure is the embed itself.
	if strings.HasPrefix(strings.ToLower(ref), "data:") {
		return c.inlineFinding(p.URL, ref, snap), nil
	}

	resolved, err := resolveSourceMapURL(p.URL, ref)
	if err != nil {
		return nil, nil
	}
	if sc != nil {
		pu, perr := url.Parse(resolved)
		if perr != nil || !sc.Allows(pu) {
			return nil, nil
		}
	}

	confirmed, status, headers, err := c.probeSourceMap(ctx, client, sc, resolved)
	if err != nil {
		// One probe failure is not a fatal scan error - leave a
		// breadcrumb and move on so a flaky CDN doesn't blank the report.
		Report(ctx, fmt.Errorf("source-map-exposure probe %s: %w", resolved, err))
		return nil, nil
	}
	if !confirmed {
		return nil, nil
	}
	return c.externalFinding(p.URL, resolved, status, headers), nil
}

// sourceMappableKind reports whether ct names a response we would expect
// to carry a sourceMappingURL pointer.
func sourceMappableKind(ct string) (string, bool) {
	if ct == "" {
		return "", false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", false
	}
	switch mediaType {
	case "application/javascript",
		"text/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"text/ecmascript":
		return "js", true
	case "text/css":
		return "css", true
	}
	return "", false
}

// findSourceMapReference returns the sourceMappingURL value advertised by
// the response, or "" when none is present. Headers win over the body
// comment: a server that emits the header is making the assertion
// explicit and overrides whatever the file's trailing comment says.
func findSourceMapReference(h http.Header, body []byte, kind string) string {
	for _, name := range []string{"SourceMap", "X-SourceMap", "X-Source-Map"} {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			return v
		}
	}
	if len(body) == 0 {
		return ""
	}
	tail := body
	if len(tail) > sourceMapTail {
		tail = tail[len(tail)-sourceMapTail:]
	}
	var capture []byte
	switch kind {
	case "js":
		if loc := sourceMapJSCommentRE.FindSubmatch(tail); loc != nil {
			capture = loc[1]
		}
	case "css":
		if loc := sourceMapCSSCommentRE.FindSubmatch(tail); loc != nil {
			capture = loc[1]
		}
	}
	return string(bytes.TrimSpace(capture))
}

// resolveSourceMapURL turns a (possibly relative) ref into the absolute
// http(s) URL the browser would fetch. Returns an error for any ref the
// scanner cannot meaningfully GET (cross-scheme jumps, javascript:,
// unresolved host).
func resolveSourceMapURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	res := b.ResolveReference(r)
	if res.Host == "" || (res.Scheme != "http" && res.Scheme != "https") {
		return "", fmt.Errorf("source map reference does not resolve to an http(s) URL: %s", ref)
	}
	return res.String(), nil
}

// probeSourceMap GETs target and reports whether the response confirms a
// served source map. Returns (false, status, headers, nil) for any
// 2xx-with-wrong-shape or non-2xx response - that is a non-finding, not
// an error.
//
// Redirects are followed: production .map files often sit behind a CDN
// redirect (asset host, cache layer, or a same-origin /assets path
// rewritten to a long-lived bucket URL) and a no-follow probe would
// silently miss a real exposure. To keep the scope guarantee intact
// when the chain crosses hosts, the final response URL is re-checked
// against sc; an out-of-scope final URL is treated as a non-finding
// rather than a confirmed leak.
func (c SourceMapExposure) probeSourceMap(ctx context.Context, client *httpclient.Client, sc *scope.Scope, target string) (bool, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, 0, nil, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return false, 0, nil, err
	}
	defer resp.Body.Close()
	if sc != nil && resp.Request != nil && resp.Request.URL != nil && !sc.Allows(resp.Request.URL) {
		// Redirect chain landed off-scope. Drop the finding rather than
		// silently report on an out-of-scope host.
		return false, resp.StatusCode, resp.Header, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, resp.StatusCode, resp.Header, nil
	}
	body, err := httpclient.ReadBody(resp, sourceMapProbeBodyCap)
	if err != nil {
		return false, resp.StatusCode, resp.Header, err
	}
	if !looksLikeSourceMap(body) {
		return false, resp.StatusCode, resp.Header, nil
	}
	return true, resp.StatusCode, resp.Header, nil
}

// looksLikeSourceMap reports whether body's leading bytes look like a
// Source Map v3 document. Anchored on the structural keys rather than
// "version":3 alone so an arbitrary JSON file carrying a version field
// cannot false-positive.
func looksLikeSourceMap(body []byte) bool {
	if !sourceMapVersionRE.Match(body) {
		return false
	}
	return sourceMapSourcesRE.Match(body) || sourceMapMappingsRE.Match(body)
}

func (c SourceMapExposure) inlineFinding(jsURL, dataURI string, snap snapshot) []Finding {
	preview := dataURI
	if len(preview) > 80 {
		preview = preview[:80] + "..."
	}
	return []Finding{{
		Check:    c.Name(),
		Target:   jsURL,
		URL:      jsURL,
		Severity: SeverityMedium,
		Title:    "inline source map embedded in deployed bundle",
		Detail: fmt.Sprintf(
			"%s carries an inline `sourceMappingURL=data:...` declaration. The full pre-minified source (original file paths, comments, variable names, and any literals the minifier preserved) is base64-embedded in the bundle every visitor downloads.",
			jsURL,
		),
		CWE:   "CWE-540",
		OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Disable inline source maps in the production build (webpack `devtool: 'hidden-source-map'` or false, Vite `build.sourcemap: false` or 'hidden', Rollup `sourcemap: false`, esbuild `--sourcemap=external` paired with deploy-time exclusion). " +
			"If maps are needed for crash deobfuscation, upload them to a private symbol service (Sentry, Datadog, Bugsnag) at build time and ship the bundle without the embedded copy.",
		Evidence:  BuildEvidence("GET", jsURL, snap.Status, snap.Headers, "sourceMappingURL: "+preview),
		DedupeKey: MakeKey(c.Name(), ScopeHost, jsURL, "inline:"+jsURL),
	}}
}

func (c SourceMapExposure) externalFinding(jsURL, mapURL string, status int, headers http.Header) []Finding {
	return []Finding{{
		Check:    c.Name(),
		Target:   jsURL,
		URL:      mapURL,
		Severity: SeverityMedium,
		Title:    "source map exposed at " + mapURL,
		Detail: fmt.Sprintf(
			"%s advertises a source map at %s, and that URL returns a valid Source Map document. The map exposes the pre-minified source: original file paths (revealing internal directory structure and naming intent), comments, full variable names, and any literals the minifier preserved (build-time constants, internal URLs, occasionally credentials).",
			jsURL, mapURL,
		),
		CWE:   "CWE-540",
		OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Stop serving .map files from the public document root. Either build production bundles without source maps (webpack `devtool: false`, Vite `build.sourcemap: false`) or generate them and upload to a private symbol service (Sentry, Datadog) for crash deobfuscation instead of the asset host. " +
			"If maps must remain on disk for tooling, add a web-server rule that returns 404 for `*.map` requests and strip the `sourceMappingURL` reference from the bundle (webpack/Vite `'hidden-source-map'`). " +
			"Before remediating, audit the leaked map for hardcoded API keys, internal hostnames, and unreleased feature names; rotate or remove anything sensitive.",
		Evidence:  BuildEvidence("GET", mapURL, status, headers, ""),
		DedupeKey: MakeKey(c.Name(), ScopeHost, jsURL, "map:"+mapURL),
	}}
}
