package injection

import (
	"bytes"
	"strings"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// pathParamKeywords are param-name substrings that mark a sink as
// "probably consumed as a filesystem path." Matched case-insensitively
// against the param name. Loose by design - false positives just cost
// a few extra probes; missing a real path param costs a missed finding.
var pathParamKeywords = []string{
	"file",
	"filename",
	"path",
	"page",
	"doc",
	"document",
	"template",
	"tpl",
	"include",
	"dir",
	"folder",
	"src",
	"view",
	"load",
	"read",
	"image",
	"img",
}

// pathSinkCandidate reports whether sink looks worth probing at
// LevelDefault. The two signals: a path-ish name, or a value that
// already carries a path-shaped character. Either one moves the sink
// out of "noise" territory; both are loose enough to err on the side
// of coverage.
func pathSinkCandidate(s lua_engine.Sink) bool {
	name := strings.ToLower(s.Name)
	for _, kw := range pathParamKeywords {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return strings.ContainsAny(s.Value, "/\\.")
}

// matchTraversalMarkers returns every TraversalMarkers entry that
// appears in body. Markers are case-sensitive byte sequences - the
// disclosed file content (passwd line shape, Windows hosts banner) is
// emitted verbatim by the OS, so a case-folded scan would only add
// false-positive surface.
func matchTraversalMarkers(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var hits []string
	for _, m := range lua_engine.TraversalMarkers() {
		if bytes.Contains(body, []byte(m)) {
			hits = append(hits, m)
		}
	}
	return hits
}
