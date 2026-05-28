package lua_engine

// This file exposes the path-traversal check's helpers to the Lua
// bridge. Sibling to path_traversal.go: forwards into the package-
// private marker matcher + sink-candidate heuristic so the Lua port
// runs the same sweep as the Go check.

// TraversalNewMarkers wraps the path-traversal check's marker-scan +
// baseline-subtraction step. body and baseline are both raw response
// bytes; the result is the TraversalMarkers entries present in body
// that did not already appear in baseline. Mirrors the SQLiErrorNewMatches
// shape used by the existing sqli-error Lua port.
func TraversalNewMarkers(body, baseline []byte) []string {
	return SubtractPatterns(matchTraversalMarkers(body), matchTraversalMarkers(baseline))
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
