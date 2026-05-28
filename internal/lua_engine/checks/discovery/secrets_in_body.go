package discovery

import (
	"mime"
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

