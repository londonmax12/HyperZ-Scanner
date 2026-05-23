package crawler

import (
	"bytes"
	"io"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/londonmax12/hyperz/internal/page"
)

// extractLinks pulls every navigable http(s) URL out of body, resolved
// against base, and returns the deduped set. Sources covered: href on
// <a>/<link>/<area>/<base>, src on <iframe>/<frame>/<img>/<script>/
// <source>/<audio>/<video>/<embed>/<track>, srcset on <img>/<source>,
// and `url=` in <meta http-equiv="refresh" content="N; url=...">.
//
// Fragments are stripped so "#section" anchors don't produce duplicate
// visits; non-http(s) schemes (mailto/javascript/ftp/...) are dropped.
func extractLinks(base *url.URL, body []byte) []string {
	links, _ := extractAll(base, body)
	return links
}

// extractForms returns every <form> in body with action resolved against
// base and inputs collected. Use this from the crawler to hand checks a
// first-class form artifact instead of letting each check re-parse HTML.
func extractForms(base *url.URL, body []byte) []page.Form {
	_, forms := extractAll(base, body)
	return forms
}

// extractAll is the single tokenizer pass that produces both link and form
// artifacts. Walking the document once keeps cost predictable on the
// MaxBodyBytes-capped buffers the crawler hands us.
func extractAll(base *url.URL, body []byte) ([]string, []page.Form) {
	if len(body) == 0 || base == nil {
		return nil, nil
	}
	// Browsers honor <base href> for the whole document regardless of where
	// the tag appears in source. Resolve it up-front so links and form
	// actions that precede the tag still use the document's effective base.
	if b := findBaseHref(base, body); b != nil {
		base = b
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	// Token data is overwritten on each call to Next; copy out anything we
	// want to keep.
	links := newLinkSink(base)
	var (
		forms      []page.Form
		current    *page.Form
		inTextarea bool
		taName     string
		taBuf      strings.Builder
	)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if err := z.Err(); err == io.EOF {
				break
			}
			// Malformed HTML: stop the walk but keep what we already found.
			// The tokenizer recovers from many bad inputs on its own; an
			// outright Err means we can't get further.
			break
		}
		switch tt {
		case html.TextToken:
			if inTextarea {
				taBuf.Write(z.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			attrs := collectAttrs(z, hasAttr)
			switch tag {
			case "a", "link", "area":
				links.addAttr(attrs, "href")
			case "iframe", "frame", "script", "embed", "track":
				links.addAttr(attrs, "src")
			case "img", "source", "audio", "video":
				links.addAttr(attrs, "src")
				links.addSrcset(attrs["srcset"])
			case "meta":
				if strings.EqualFold(attrs["http-equiv"], "refresh") {
					if u := metaRefreshURL(attrs["content"]); u != "" {
						links.addRaw(u)
					}
				}
			case "form":
				if current != nil {
					// Nested <form> is invalid but real - close the outer
					// before opening the inner so we don't lose it.
					forms = append(forms, *current)
				}
				current = newForm(base, attrs)
			case "input":
				if current != nil {
					if in, ok := inputFromAttrs(attrs); ok {
						current.Inputs = append(current.Inputs, in)
					}
				}
			case "select":
				if current != nil {
					if name := attrs["name"]; name != "" {
						current.Inputs = append(current.Inputs, page.FormInput{
							Name: name, Type: "select", Value: attrs["value"],
						})
					}
				}
			case "textarea":
				if current != nil {
					inTextarea = true
					taName = attrs["name"]
					taBuf.Reset()
				}
			case "button":
				if current != nil {
					if name := attrs["name"]; name != "" {
						t := strings.ToLower(attrs["type"])
						if t == "" {
							t = "submit"
						}
						current.Inputs = append(current.Inputs, page.FormInput{
							Name: name, Type: t, Value: attrs["value"],
						})
					}
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			switch tag {
			case "form":
				if current != nil {
					forms = append(forms, *current)
					current = nil
				}
			case "textarea":
				if current != nil && inTextarea && taName != "" {
					current.Inputs = append(current.Inputs, page.FormInput{
						Name: taName, Type: "textarea", Value: taBuf.String(),
					})
				}
				inTextarea = false
				taName = ""
				taBuf.Reset()
			}
		}
	}
	if current != nil {
		// Unclosed <form>: still surface it. Real-world HTML drops the
		// closing tag often enough that ignoring this would lose forms.
		forms = append(forms, *current)
	}
	return links.out, forms
}

// findBaseHref scans body for the first <base href="..."> and resolves it
// against base. Returns nil when no usable tag is present so the caller
// keeps the original base. Only the first valid <base> wins, matching the
// HTML spec and browser behavior; subsequent tags are ignored.
//
// The pre-pass is intentionally cheap: it stops as soon as a usable href
// is found, and otherwise costs one tokenizer walk over the already
// MaxBodyBytes-capped buffer.
func findBaseHref(base *url.URL, body []byte) *url.URL {
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return nil
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if string(name) != "base" || !hasAttr {
			continue
		}
		attrs := collectAttrs(z, hasAttr)
		href := strings.TrimSpace(attrs["href"])
		if href == "" {
			// <base> without an href doesn't set the document base; keep
			// scanning for a later one that does.
			continue
		}
		u, err := url.Parse(href)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(u)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		return resolved
	}
}

// collectAttrs pulls every attribute on the current token into a map.
// HTML attribute names are case-insensitive so they're lowercased; the
// last-wins rule handles duplicate attributes (also matching browsers).
func collectAttrs(z *html.Tokenizer, hasAttr bool) map[string]string {
	if !hasAttr {
		return nil
	}
	m := map[string]string{}
	for {
		k, v, more := z.TagAttr()
		m[strings.ToLower(string(k))] = string(v)
		if !more {
			break
		}
	}
	return m
}

// linkSink resolves and dedupes URLs as the walker discovers them. Keeping
// the dedupe map here (not in the caller) lets us split URL discovery across
// the many tag-handler branches above without each one re-implementing it.
type linkSink struct {
	base *url.URL
	seen map[string]struct{}
	out  []string
}

func newLinkSink(base *url.URL) *linkSink {
	return &linkSink{base: base, seen: map[string]struct{}{}}
}

func (s *linkSink) addAttr(attrs map[string]string, key string) {
	if v := attrs[key]; v != "" {
		s.addRaw(v)
	}
}

// addSrcset parses an HTML `srcset` value into its candidate URLs. The
// format is `url descriptor, url descriptor, ...` where descriptor is
// optional ("2x" or "800w"). We split by comma (URLs can't contain a
// bare comma without escaping) and take the first whitespace-separated
// token of each chunk.
func (s *linkSink) addSrcset(v string) {
	if v == "" {
		return
	}
	for _, candidate := range strings.Split(v, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		// First whitespace token is the URL; the rest (if any) is the
		// density / width descriptor.
		if i := strings.IndexAny(candidate, " \t"); i >= 0 {
			candidate = candidate[:i]
		}
		s.addRaw(candidate)
	}
}

func (s *linkSink) addRaw(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	resolved := s.base.ResolveReference(u)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return
	}
	resolved.Fragment = ""
	abs := resolved.String()
	if _, ok := s.seen[abs]; ok {
		return
	}
	s.seen[abs] = struct{}{}
	s.out = append(s.out, abs)
}

// metaRefreshURL parses the content attribute of <meta http-equiv="refresh">
// and returns the absolute (or relative, for the caller to resolve) target.
// Format is `<seconds>` or `<seconds>; url=<target>`. The url= prefix is
// case-insensitive and may be quoted.
func metaRefreshURL(content string) string {
	if content == "" {
		return ""
	}
	// Locate the delimiter between the delay and the rest.
	idx := strings.IndexAny(content, ";,")
	if idx < 0 {
		// Pure-delay form (no URL): nothing to extract. We also accept the
		// non-standard "url=..." with no preceding delay below, but pure
		// numbers / whitespace produce no link.
		if _, err := strconv.Atoi(strings.TrimSpace(content)); err == nil {
			return ""
		}
	}
	rest := content
	if idx >= 0 {
		rest = content[idx+1:]
	}
	rest = strings.TrimSpace(rest)
	// Strip the optional "url=" prefix.
	if len(rest) >= 4 && strings.EqualFold(rest[:4], "url=") {
		rest = strings.TrimSpace(rest[4:])
	}
	rest = strings.Trim(rest, `"'`)
	return rest
}

// newForm builds a Form from a <form> tag's attributes, resolving the
// action against base. Forms whose action resolves to a non-http(s)
// scheme are still returned (with Action empty) so checks can decide
// whether to skip; this keeps the extractor's contract simple.
func newForm(base *url.URL, attrs map[string]string) *page.Form {
	method := strings.ToUpper(strings.TrimSpace(attrs["method"]))
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "POST" {
		// HTML5 allows dialog/DELETE/PUT etc. via the formmethod attribute,
		// but the form-level method is GET or POST only. Anything else
		// browsers treat as GET.
		method = "GET"
	}
	action := ""
	if raw := strings.TrimSpace(attrs["action"]); raw != "" {
		if u, err := url.Parse(raw); err == nil {
			resolved := base.ResolveReference(u)
			if resolved.Scheme == "http" || resolved.Scheme == "https" {
				resolved.Fragment = ""
				action = resolved.String()
			}
		}
	} else {
		// Empty / missing action posts back to the page itself.
		clone := *base
		clone.Fragment = ""
		action = clone.String()
	}
	return &page.Form{Method: method, Action: action}
}

// inputFromAttrs builds a FormInput from an <input> tag. Returns ok=false
// for unnamed controls (browsers don't submit them) and for input types
// the scanner has no business poking at - submit/reset/image/hidden are
// kept (hidden is high-signal for CSRF/IDOR), button/file we still pass
// through so checks can decide what to do with them.
func inputFromAttrs(attrs map[string]string) (page.FormInput, bool) {
	name := attrs["name"]
	if name == "" {
		return page.FormInput{}, false
	}
	t := strings.ToLower(strings.TrimSpace(attrs["type"]))
	if t == "" {
		t = "text"
	}
	return page.FormInput{Name: name, Type: t, Value: attrs["value"]}, true
}
