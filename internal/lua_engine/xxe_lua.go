package lua_engine

// This file exposes the XXE check's private helpers to the Lua bridge.
// Sibling to xxe.go: every helper here forwards into a package-private
// xxe.go identifier so the Go check stays the single source of truth
// and a future move of the check into its own subpackage carries these
// shims along without crossing a bridge boundary.

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
