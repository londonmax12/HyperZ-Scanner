package xss

import (
	"strings"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// payloadsForContexts maps the bare-canary reflection contexts onto the
// curated lua_engine.PayloadXSS variants whose breakout shape matches each context.
//
// At lua_engine.LevelDefault, output is exactly the context-matched set, deduped by
// payload name so repeated contexts (token echoed twice in the same shape)
// don't double the request count.
//
// At lua_engine.LevelAggressive, every payload is still tried so a breakout achievable
// through an alternate shape (sloppy attribute echo, double-rendered context)
// is caught - but the context-matched payloads are front-loaded so the
// probe's first-success short-circuit can return after one or two requests
// in the common case instead of grinding through the full catalog.
func payloadsForContexts(refs []lua_engine.Reflection, level lua_engine.Level) []lua_engine.Payload {
	matched := selectByContext(refs)
	if level < lua_engine.LevelAggressive {
		return matched
	}
	all := lua_engine.PayloadsFor(lua_engine.PayloadXSS)
	matchedSet := make(map[string]struct{}, len(matched))
	for _, p := range matched {
		matchedSet[p.Name] = struct{}{}
	}
	out := make([]lua_engine.Payload, 0, len(all))
	out = append(out, matched...)
	for _, p := range all {
		if _, dup := matchedSet[p.Name]; dup {
			continue
		}
		out = append(out, p)
	}
	return out
}

// selectByContext returns the context-matched payload subset, deduped by
// name and ordered by first appearance of each context in refs.
func selectByContext(refs []lua_engine.Reflection) []lua_engine.Payload {
	byName := map[string]lua_engine.Payload{}
	for _, p := range lua_engine.PayloadsFor(lua_engine.PayloadXSS) {
		byName[p.Name] = p
	}
	seen := map[string]struct{}{}
	var out []lua_engine.Payload
	push := func(names ...string) {
		for _, n := range names {
			if _, dup := seen[n]; dup {
				continue
			}
			p, ok := byName[n]
			if !ok {
				continue
			}
			out = append(out, p)
			seen[n] = struct{}{}
		}
	}
	for _, r := range refs {
		switch r.Context {
		case lua_engine.CtxHTMLText:
			// Free HTML on both sides; any tag-injection payload executes.
			push("html-svg-onload", "html-img-onerror")
		case lua_engine.CtxAttrUnquoted:
			// In tag-content / unquoted-attr state the parser does not
			// leave attribute mode on a bare `<`; we need `>` first to
			// close the host tag before our `<svg ...>` can form.
			push("attr-unquoted-break")
		case lua_engine.CtxAttrDoubleQuoted:
			push("attr-double-break")
		case lua_engine.CtxAttrSingleQuoted:
			push("attr-single-break")
		case lua_engine.CtxScriptText:
			// Already inside <script> but not in a string literal: bare
			// JS executes directly. Leading `;` makes the payload safe
			// at both statement and expression positions.
			push("js-bare-break")
		case lua_engine.CtxScriptStringDouble:
			push("js-string-double-break")
		case lua_engine.CtxScriptStringSingle:
			push("js-string-single-break")
		case lua_engine.CtxHTMLComment, lua_engine.CtxHeaderValue:
			// Comment requires a `-->` escape we do not currently render;
			// header-value reflection isn't XSS by itself. Default-level
			// scan skips both; aggressive level still hits everything via
			// the catalog-wide tail of payloadsForContexts.
		}
	}
	return out
}

// contextSummary returns a comma-separated, dedup-ordered list of context
// names for use in finding text. Source order is preserved so the first
// reflection's context leads the rendering.
func contextSummary(refs []lua_engine.Reflection) string {
	seen := map[lua_engine.Context]struct{}{}
	var names []string
	for _, r := range refs {
		if _, dup := seen[r.Context]; dup {
			continue
		}
		seen[r.Context] = struct{}{}
		names = append(names, r.Context.String())
	}
	return strings.Join(names, ", ")
}
