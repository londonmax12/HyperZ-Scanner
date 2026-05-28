package lua_engine

import "net/http"

// This file exposes the source-map-exposure check's helpers to the
// Lua bridge. Sibling to source_map_exposure.go: forwards into the
// package-private per-stage helpers so the regex anchors stay in one
// place.

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
