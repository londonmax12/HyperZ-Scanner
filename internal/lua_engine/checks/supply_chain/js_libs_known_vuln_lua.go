package supply_chain

import "sort"

// This file exposes the js-libs-known-vuln check's helpers to the Lua
// bridge. Sibling to js_libs_known_vuln.go: forwards into the
// package-private extractLibraries scanner so the fingerprint
// catalogue + regex match stay in Go.

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
