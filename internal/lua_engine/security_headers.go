package lua_engine

import (
	"mime"
)

// isHTMLContentType reports whether ct names an HTML document. Parameters
// such as `; charset=utf-8` are stripped before comparison so a perfectly
// labeled response is not skipped on a technicality. A missing or
// unparseable Content-Type returns false: a server that does not declare
// its body's type is not the audience for browser-rendering headers.
func isHTMLContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "text/html" || mediaType == "application/xhtml+xml"
}
