package lua_engine

import (
	"regexp"
)

// MixedContent scans the HTML body of an HTTPS page for subresources loaded
// over plaintext http://. Active loads (script, iframe, link, form) are
// blocked or downgraded by browsers and rated High; passive loads (img,
// audio, video, etc.) are rated Low.
type MixedContent struct{}

// mixedContentBodyCap bounds how much of the response we parse. Most HTML
// documents fit comfortably under 2 MiB; past that we accept the risk of
// missing late-document references in exchange for a predictable cost.
const mixedContentBodyCap = 2 << 20

// mixedContentTags lists the HTML elements that load subresources, which
// attribute carries the URL, and whether the load is "active" (executes or
// styles the page) or "passive" (decorative / data-only). Browsers block
// active mixed content by default and either upgrade or warn on passive.
//
// <a href> is intentionally absent;	 anchor links are navigation, not
// subresource loads, so they don't constitute mixed content.
//
// All <link> uses are treated as active. The common cases (stylesheet,
// preload, modulepreload) are active; rel="icon" is technically not, but
// the simpler classification beats parsing rel here.
var mixedContentTags = map[string]struct {
	attr   string
	active bool
}{
	"script": {"src", true},
	"iframe": {"src", true},
	"frame":  {"src", true},
	"link":   {"href", true},
	"form":   {"action", true},
	"img":    {"src", false},
	"video":  {"src", false},
	"audio":  {"src", false},
	"source": {"src", false},
	"embed":  {"src", false},
	"track":  {"src", false},
}

var (
	mixedCommentRE = regexp.MustCompile(`(?s)<!--.*?-->`)
	mixedTagRE     = regexp.MustCompile(`(?is)<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>`)
	mixedAttrRE    = map[string]*regexp.Regexp{
		"src":    regexp.MustCompile(`(?is)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`),
		"href":   regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`),
		"action": regexp.MustCompile(`(?is)\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`),
	}
)
