package lua_engine

import (
	"mime"
	"regexp"
	"strings"
)

// secretHit groups every position where one specific secret value was
// found in the body. Multiple occurrences of the same token collapse to
// one hit (with count incremented) so a JS bundle that bakes a key into
// a constant and then references it five times still produces one
// detail entry instead of five.
type secretHit struct {
	pattern secretPattern
	raw     string
	count   int
}

// isScannableContentType reports whether ct names a body type worth
// scanning for textual secret patterns. Binary types (images, fonts,
// archives, video) are skipped because regex over their bytes is noise
// for no signal. Unknown / unparseable / absent Content-Type defaults
// to scannable: a server that does not declare its type is exactly the
// kind of careless surface that may also ship plaintext credentials,
// and the patterns are anchored tightly enough that scanning a small
// binary blob is harmless.
func isScannableContentType(ct string) bool {
	if ct == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return true
	}
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	// Catch the family of structured types that piggyback on JSON / XML
	// (e.g. application/vnd.api+json, image/svg+xml). Checked BEFORE the
	// image/ / audio/ rejects below so image/svg+xml is still scanned -
	// SVGs routinely embed inline <script> with constants.
	if strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml") {
		return true
	}
	if strings.HasPrefix(mediaType, "image/") ||
		strings.HasPrefix(mediaType, "audio/") ||
		strings.HasPrefix(mediaType, "video/") ||
		strings.HasPrefix(mediaType, "font/") {
		return false
	}
	switch mediaType {
	case "application/json",
		"application/javascript",
		"application/ecmascript",
		"application/xml",
		"application/xhtml+xml",
		"application/ld+json",
		"application/yaml",
		"application/x-yaml",
		"application/graphql",
		"application/x-www-form-urlencoded":
		return true
	case "application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
		"application/x-tar",
		"application/wasm":
		return false
	}
	return false
}

// hasNearbyContext reports whether contextRE matches inside a window of
// [secretContextWindow] bytes on each side of the candidate match
// spanning [start, end). It exists to gate ambiguously-shaped patterns
// (e.g. Mailgun's key-<32hex>) so a hit is kept only when there is a
// vendor-identifying token in the immediate neighbourhood, not anywhere
// in the body.
func hasNearbyContext(body []byte, start, end int, contextRE *regexp.Regexp) bool {
	winStart := start - secretContextWindow
	if winStart < 0 {
		winStart = 0
	}
	winEnd := end + secretContextWindow
	if winEnd > len(body) {
		winEnd = len(body)
	}
	return contextRE.Match(body[winStart:winEnd])
}

// redactSecret produces the short, non-reversible form of raw that is
// safe to embed in a report. The first four and last four characters
// are kept so a reviewer can recognise the same key across two
// findings; everything in the middle becomes a single ellipsis. Very
// short matches and PEM block headers (which carry no secret material
// themselves) are special-cased so the output stays meaningful.
func redactSecret(raw string) string {
	if strings.HasPrefix(raw, "-----BEGIN") {
		// The PEM header line is not itself secret; surface it verbatim
		// so the reviewer knows which key type leaked without us echoing
		// any of the encoded body that follows.
		return raw + " (key body redacted)"
	}
	if len(raw) <= 12 {
		return strings.Repeat("*", len(raw))
	}
	return raw[:4] + "..." + raw[len(raw)-4:]
}
