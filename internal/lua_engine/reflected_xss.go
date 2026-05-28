package lua_engine

import "strings"

// payloadsForContexts maps the bare-canary reflection contexts onto the
// curated PayloadXSS variants whose breakout shape matches each context.
//
// At LevelDefault, output is exactly the context-matched set, deduped by
// payload name so repeated contexts (token echoed twice in the same shape)
// don't double the request count.
//
// At LevelAggressive, every payload is still tried so a breakout achievable
// through an alternate shape (sloppy attribute echo, double-rendered context)
// is caught - but the context-matched payloads are front-loaded so the
// probe's first-success short-circuit can return after one or two requests
// in the common case instead of grinding through the full catalog.
func payloadsForContexts(refs []Reflection, level Level) []Payload {
	matched := selectByContext(refs)
	if level < LevelAggressive {
		return matched
	}
	all := PayloadsFor(PayloadXSS)
	matchedSet := make(map[string]struct{}, len(matched))
	for _, p := range matched {
		matchedSet[p.Name] = struct{}{}
	}
	out := make([]Payload, 0, len(all))
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
func selectByContext(refs []Reflection) []Payload {
	byName := map[string]Payload{}
	for _, p := range PayloadsFor(PayloadXSS) {
		byName[p.Name] = p
	}
	seen := map[string]struct{}{}
	var out []Payload
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
		case CtxHTMLText:
			// Free HTML on both sides; any tag-injection payload executes.
			push("html-svg-onload", "html-img-onerror")
		case CtxAttrUnquoted:
			// In tag-content / unquoted-attr state the parser does not
			// leave attribute mode on a bare `<`; we need `>` first to
			// close the host tag before our `<svg ...>` can form.
			push("attr-unquoted-break")
		case CtxAttrDoubleQuoted:
			push("attr-double-break")
		case CtxAttrSingleQuoted:
			push("attr-single-break")
		case CtxScriptText:
			// Already inside <script> but not in a string literal: bare
			// JS executes directly. Leading `;` makes the payload safe
			// at both statement and expression positions.
			push("js-bare-break")
		case CtxScriptStringDouble:
			push("js-string-double-break")
		case CtxScriptStringSingle:
			push("js-string-single-break")
		case CtxHTMLComment, CtxHeaderValue:
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
func contextSummary(refs []Reflection) string {
	seen := map[Context]struct{}{}
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
