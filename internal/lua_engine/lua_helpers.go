package lua_engine

import (
	"bytes"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// This file exposes the small set of truly general helpers the Lua
// bridge calls into from ported checks - the ones that are not
// owned by any single check. Per-check shims live in their
// <check>_lua.go siblings so a future move of the check into its own
// subpackage carries the shims with it.
//
// What stays general here:
//   * IsHTMLContentType - the Content-Type filter shared by half the
//     passive checks; the Lua ports re-use it so a change to "what
//     counts as HTML" lands once.
//   * ParseSetCookies - lifts http.Response.Cookies() onto a bare
//     http.Header so the cookie-attributes Lua port does not have to
//     build a fake *http.Response.
//   * IterHTMLTags / HTMLTag / HTMLAttr - the tokenizer pair the
//     HTML-walking ports (sri-missing, target-blank-noopener, form-
//     autocomplete, ...) re-use so each does not reimplement the same
//     html.Tokenizer loop in Lua.
//   * ResolveURLRef - the relative / absolute URL pair the same
//     HTML-walking ports use to resolve hrefs / srcs without each
//     re-listing the skip-prefix set.

// IsHTMLContentType reports whether ct names an HTML document. Parameters
// such as `; charset=utf-8` are stripped before comparison so a perfectly
// labeled response is not skipped on a technicality. A missing or
// unparseable Content-Type returns false: a server that does not declare
// its body's type is not the audience for browser-rendering headers.
//
// Used by every passive check that gates on "only run for HTML responses"
// and exposed to the Lua bridge so the same rule fires on both sides.
func IsHTMLContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "text/html" || mediaType == "application/xhtml+xml"
}

// ParseSetCookies returns the cookies represented by the Set-Cookie
// headers on h, in the order net/http parses them. Re-uses
// http.Response.Cookies so the parse behavior is the same one cookie-
// handling code in this repo already relies on; the synthetic Response
// is throwaway, only its Header field is consulted.
func ParseSetCookies(h http.Header) []*http.Cookie {
	return (&http.Response{Header: h}).Cookies()
}

// HTMLTag is one tokenizer-emitted start (or self-closing) tag. Attrs
// preserves attribute order so a check that needs to distinguish
// duplicate attribute names (browsers take the first) sees the same
// order html.Tokenizer reports.
type HTMLTag struct {
	Name  string
	Attrs []HTMLAttr
}

// HTMLAttr is one attribute on an HTMLTag. Name is lower-cased to
// match the case-insensitive way browsers compare HTML attribute
// names; Value is preserved verbatim so the Lua port can echo it back
// in finding text.
type HTMLAttr struct {
	Name  string
	Value string
}

// IterHTMLTags walks body once and returns every start / self-closing
// tag whose lower-cased name is in interesting. interesting may be nil
// to emit every tag, but every existing Lua port supplies a small set
// so the bridge does not allocate one HTMLTag per <div>.
//
// Attribute names are lower-cased; values are preserved as the
// tokenizer reports them. The walker silently ignores end-tag tokens,
// text, comments, and doctype - the consumers all want "the start
// shape of tags I care about" and would discard the rest anyway.
func IterHTMLTags(body []byte, interesting map[string]bool) []HTMLTag {
	if len(body) == 0 {
		return nil
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	var out []HTMLTag
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		tag := string(name)
		if interesting != nil && !interesting[tag] {
			continue
		}
		var attrs []HTMLAttr
		if hasAttr {
			for {
				k, v, more := z.TagAttr()
				attrs = append(attrs, HTMLAttr{
					Name:  strings.ToLower(string(k)),
					Value: string(v),
				})
				if !more {
					break
				}
			}
		}
		out = append(out, HTMLTag{Name: tag, Attrs: attrs})
	}
	return out
}

// ResolveURLRef returns the absolute form of ref when interpreted
// relative to base. Returns ok=false for refs the Lua port should
// skip (empty, javascript:, data:, mailto:, tel:, fragment-only) so a
// single boundary check in the Go side keeps the per-port skip lists
// from drifting out of sync.
func ResolveURLRef(base, ref string) (resolved *url.URL, ok bool) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return nil, false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "blob:") ||
		strings.HasPrefix(lower, "#") {
		return nil, false
	}
	b, err := url.Parse(base)
	if err != nil {
		return nil, false
	}
	r, err := url.Parse(trimmed)
	if err != nil {
		return nil, false
	}
	res := b.ResolveReference(r)
	if res.Host == "" {
		return nil, false
	}
	return res, true
}
