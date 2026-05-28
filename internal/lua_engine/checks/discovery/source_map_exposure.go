package discovery

import (
	"bytes"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	// sourceMapTail is how many trailing bytes of the host body we scan
	// for the comment marker. Bundlers always emit it on the last line;
	// 4 KiB is a generous overestimate that tolerates a license footer
	// or post-build banner pushed in after the bundler ran.
	sourceMapTail = 4 << 10
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
