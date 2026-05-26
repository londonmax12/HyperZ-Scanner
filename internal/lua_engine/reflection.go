package lua_engine

import (
	"bytes"
	"net/http"
	"strings"
)

// Context names the HTML / JS surrounding a reflected token. The point of
// classifying reflections (rather than just yes/no detection) is that the
// payload an active check needs depends on context: a token landing in a
// double-quoted attribute is exploitable with `">` but not with `'>`, and a
// token inside a `<script>"..."</script>` literal is exploitable with `";`
// but not with bare HTML tags. Checks pick payloads off the corresponding
// PayloadXSS slot once the context is known.
type Context int

const (
	// CtxNone is the zero value: no reflection found. Returned only via
	// the empty-slice shape - Reflection.Context itself is never set to
	// CtxNone on a real hit.
	CtxNone Context = iota
	// CtxHeaderValue: the token appeared in a response header value.
	CtxHeaderValue
	// CtxHTMLText: the token landed in HTML text content, outside any tag
	// or comment. Most dangerous context: a bare `<svg>` payload executes.
	CtxHTMLText
	// CtxHTMLComment: the token landed inside `<!-- ... -->`. Closing
	// `-->` breaks back into text; on its own the comment is inert.
	CtxHTMLComment
	// CtxAttrDoubleQuoted: inside `attr="..."`. Breakout needs `"`.
	CtxAttrDoubleQuoted
	// CtxAttrSingleQuoted: inside `attr='...'`. Breakout needs `'`.
	CtxAttrSingleQuoted
	// CtxAttrUnquoted: inside a tag but not inside a quoted attribute
	// value. Covers both attribute-name and unquoted-attribute-value
	// areas; either way, whitespace or `>` breaks tag structure.
	CtxAttrUnquoted
	// CtxScriptText: inside a `<script>` block, not inside a JS string.
	// The reflection is parsed as JavaScript source - injecting code is
	// trivially possible.
	CtxScriptText
	// CtxScriptStringDouble: inside `"..."` in a `<script>` block.
	// Breakout needs `";`.
	CtxScriptStringDouble
	// CtxScriptStringSingle: inside `'...'` in a `<script>` block.
	CtxScriptStringSingle
)

func (c Context) String() string {
	switch c {
	case CtxHeaderValue:
		return "header-value"
	case CtxHTMLText:
		return "html-text"
	case CtxHTMLComment:
		return "html-comment"
	case CtxAttrDoubleQuoted:
		return "attr-double-quoted"
	case CtxAttrSingleQuoted:
		return "attr-single-quoted"
	case CtxAttrUnquoted:
		return "attr-unquoted"
	case CtxScriptText:
		return "script-text"
	case CtxScriptStringDouble:
		return "script-string-double"
	case CtxScriptStringSingle:
		return "script-string-single"
	default:
		return "none"
	}
}

// Reflection is one location where a probe canary was echoed back. Offset is
// the byte index into the body where the match starts; for header hits
// Offset is -1 and Header carries the header name. Multiple Reflections for
// the same token in the same response are returned in source order so
// callers can show "first hit" evidence and a count.
type Reflection struct {
	Context Context
	Offset  int
	Header  string
}

// FindReflections scans body and headers for token and returns every match
// along with the HTML / JS context surrounding it. Returns nil when token is
// empty or never appears.
//
// The body scanner is a single-pass HTML state machine: lenient about
// malformed markup (real targets emit plenty), correct on the canonical
// cases that drive XSS exploitability decisions (text, comment, single/
// double-quoted attribute, script body, JS string literals). It does not
// claim full HTML5 conformance - context is a hint to the payload selector,
// not an authoritative parse.
func FindReflections(body []byte, headers http.Header, token string) []Reflection {
	if token == "" {
		return nil
	}
	var out []Reflection
	for name, values := range headers {
		for _, v := range values {
			if strings.Contains(v, token) {
				out = append(out, Reflection{Context: CtxHeaderValue, Offset: -1, Header: name})
			}
		}
	}
	if len(body) == 0 {
		return out
	}
	tokenBytes := []byte(token)
	state := stText
	i := 0
	for i < len(body) {
		if i+len(tokenBytes) <= len(body) && bytes.Equal(body[i:i+len(tokenBytes)], tokenBytes) {
			out = append(out, Reflection{Context: state.context(), Offset: i})
			// Canaries are alphanumeric (see NewCanary), so they contain
			// no HTML / JS state-changing bytes - safe to step past in
			// bulk without re-running the machine over each one.
			i += len(tokenBytes)
			continue
		}
		next, advance := stepState(body, i, state)
		state = next
		if advance <= 0 {
			advance = 1
		}
		i += advance
	}
	return out
}

// HasReflection is a convenience wrapper: true when token appears anywhere
// in body or any header value. Use FindReflections when context classification
// matters (XSS payload selection); use this when only presence matters
// (e.g. confirming a canary round-tripped on a request-smuggling probe).
func HasReflection(body []byte, headers http.Header, token string) bool {
	if token == "" {
		return false
	}
	if len(body) > 0 && bytes.Contains(body, []byte(token)) {
		return true
	}
	for _, values := range headers {
		for _, v := range values {
			if strings.Contains(v, token) {
				return true
			}
		}
	}
	return false
}

// ctxState is the internal state of the body scanner. Kept separate from the
// public Context so the scanner can carry transient state (e.g. "inside a
// start tag, not yet decided whether it's <script>") without leaking into
// the Reflection API.
type ctxState int

const (
	stText ctxState = iota
	stTag
	stAttrDouble
	stAttrSingle
	stComment
	stScript
	stScriptDouble
	stScriptSingle
)

func (s ctxState) context() Context {
	switch s {
	case stText:
		return CtxHTMLText
	case stTag:
		return CtxAttrUnquoted
	case stAttrDouble:
		return CtxAttrDoubleQuoted
	case stAttrSingle:
		return CtxAttrSingleQuoted
	case stComment:
		return CtxHTMLComment
	case stScript:
		return CtxScriptText
	case stScriptDouble:
		return CtxScriptStringDouble
	case stScriptSingle:
		return CtxScriptStringSingle
	}
	return CtxNone
}

// stepState advances the scanner by one logical step. Returns the next state
// plus the number of bytes consumed (>=1). The two-return shape lets multi-
// byte sequences (e.g. "<!--", "</script>") jump the cursor without losing
// state-machine purity.
func stepState(body []byte, i int, st ctxState) (ctxState, int) {
	c := body[i]
	switch st {
	case stText:
		if c != '<' {
			return stText, 1
		}
		if hasPrefix(body, i, "<!--") {
			return stComment, 4
		}
		// <script ...>: jump the cursor to just past the closing `>` of
		// the start tag, then enter SCRIPT. Without this jump, the
		// scanner would walk through `<script ...>` as TAG state and
		// misclassify any token landing on a `src=` URL inside the
		// script start tag.
		if matchesScriptOpen(body, i) {
			end := indexByteFrom(body, i+1, '>')
			if end < 0 {
				return stScript, len(body) - i
			}
			return stScript, end - i + 1
		}
		return stTag, 1
	case stTag:
		switch c {
		case '>':
			return stText, 1
		case '"':
			return stAttrDouble, 1
		case '\'':
			return stAttrSingle, 1
		default:
			return stTag, 1
		}
	case stAttrDouble:
		if c == '"' {
			return stTag, 1
		}
		return stAttrDouble, 1
	case stAttrSingle:
		if c == '\'' {
			return stTag, 1
		}
		return stAttrSingle, 1
	case stComment:
		if hasPrefix(body, i, "-->") {
			return stText, 3
		}
		return stComment, 1
	case stScript:
		switch c {
		case '"':
			return stScriptDouble, 1
		case '\'':
			return stScriptSingle, 1
		case '<':
			if hasPrefixFold(body, i, "</script") {
				end := indexByteFrom(body, i+1, '>')
				if end < 0 {
					return stText, len(body) - i
				}
				return stText, end - i + 1
			}
			return stScript, 1
		default:
			return stScript, 1
		}
	case stScriptDouble:
		if c == '\\' && i+1 < len(body) {
			return stScriptDouble, 2
		}
		if c == '"' {
			return stScript, 1
		}
		return stScriptDouble, 1
	case stScriptSingle:
		if c == '\\' && i+1 < len(body) {
			return stScriptSingle, 2
		}
		if c == '\'' {
			return stScript, 1
		}
		return stScriptSingle, 1
	}
	return stText, 1
}

func hasPrefix(body []byte, i int, prefix string) bool {
	if i+len(prefix) > len(body) {
		return false
	}
	for j := 0; j < len(prefix); j++ {
		if body[i+j] != prefix[j] {
			return false
		}
	}
	return true
}

// hasPrefixFold compares prefix against body[i:] case-insensitively for ASCII
// letters; non-letter bytes must match exactly. Used to spot `<script` /
// `</script` without forcing the body through a lower-case pass.
func hasPrefixFold(body []byte, i int, prefix string) bool {
	if i+len(prefix) > len(body) {
		return false
	}
	for j := 0; j < len(prefix); j++ {
		a := body[i+j]
		b := prefix[j]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// matchesScriptOpen reports whether body[i:] begins with `<script` followed by
// a non-letter (space, `>`, `/`, etc.). The trailing non-letter check
// prevents matching `<scripting>` as a script open tag.
func matchesScriptOpen(body []byte, i int) bool {
	if !hasPrefixFold(body, i, "<script") {
		return false
	}
	next := i + len("<script")
	if next >= len(body) {
		return true
	}
	c := body[next]
	return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
}

func indexByteFrom(body []byte, start int, c byte) int {
	if start >= len(body) {
		return -1
	}
	off := bytes.IndexByte(body[start:], c)
	if off < 0 {
		return -1
	}
	return start + off
}
