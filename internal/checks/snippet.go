package checks

import (
	"bytes"
	"strings"
)

// snippetWindow is the byte radius around a needle that snippet returns on
// each side. Sized to give a reviewer enough surrounding HTML / driver-trace
// structure to judge the hit without dragging the whole response body into
// the finding evidence.
const snippetWindow = 120

// snippet returns up to ~snippetWindow bytes of body either side of the
// first occurrence of needle, with surrounding whitespace trimmed.
//
// When caseInsensitive is true the offset search is performed on a
// lowercased copy of body and needle, but the slice returned is sliced
// from the ORIGINAL body so the snippet preserves the casing the server
// actually sent. Use it for matches that were themselves found case-
// insensitively (SQL error patterns); pass false for byte-exact matches
// (XSS payload round-trip).
//
// Returns string(needle) when needle isn't present - defensive only;
// callers should already have established a match before calling.
func snippet(body, needle []byte, caseInsensitive bool) string {
	if len(needle) == 0 {
		return ""
	}
	hay, ndl := body, needle
	if caseInsensitive {
		hay = bytes.ToLower(body)
		ndl = bytes.ToLower(needle)
	}
	idx := bytes.Index(hay, ndl)
	if idx < 0 {
		return string(needle)
	}
	start := idx - snippetWindow
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + snippetWindow
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(string(body[start:end]))
}
