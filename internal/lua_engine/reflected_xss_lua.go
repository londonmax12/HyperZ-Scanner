package lua_engine

import "net/http"

// This file exposes the reflected-xss check's helpers to the Lua
// bridge. Sibling to reflected_xss.go (and reflection.go): forwards
// into the package-private payload selector + context summary so the
// Lua port picks the same context-matched payload subset and renders
// the same summary the Go check does.

// XSSPayloadsForContextsLua exposes payloadsForContexts so the Lua
// reflected-xss port picks the same context-matched payload subset
// (deduped, source-ordered) the Go check uses. Reflections arrive as
// the context-string slice the bridge already exposes via FindReflections.
func XSSPayloadsForContextsLua(contexts []string, level string) []SQLiErrorPayload {
	parsedLevel, err := ParseLevel(level)
	if err != nil {
		parsedLevel = LevelDefault
	}
	refs := make([]Reflection, 0, len(contexts))
	for _, name := range contexts {
		refs = append(refs, Reflection{Context: contextFromString(name)})
	}
	picked := payloadsForContexts(refs, parsedLevel)
	out := make([]SQLiErrorPayload, 0, len(picked))
	for _, p := range picked {
		out = append(out, SQLiErrorPayload{Name: p.Name, Template: p.Template})
	}
	return out
}

// XSSContextSummaryLua returns the comma-separated, dedup-ordered list
// of context names from contexts. Mirrors contextSummary.
func XSSContextSummaryLua(contexts []string) string {
	refs := make([]Reflection, 0, len(contexts))
	for _, name := range contexts {
		refs = append(refs, Reflection{Context: contextFromString(name)})
	}
	return contextSummary(refs)
}

// contextFromString is the inverse of Context.String. Used by the Lua
// bridge to round-trip context strings back into the typed enum so the
// payload selector + summary functions get the same values FindReflections
// produced.
func contextFromString(name string) Context {
	switch name {
	case "header-value":
		return CtxHeaderValue
	case "html-text":
		return CtxHTMLText
	case "html-comment":
		return CtxHTMLComment
	case "attr-double-quoted":
		return CtxAttrDoubleQuoted
	case "attr-single-quoted":
		return CtxAttrSingleQuoted
	case "attr-unquoted":
		return CtxAttrUnquoted
	case "script-text":
		return CtxScriptText
	case "script-string-double":
		return CtxScriptStringDouble
	case "script-string-single":
		return CtxScriptStringSingle
	}
	return CtxNone
}

// FindReflectionsLua wraps FindReflections so the Lua bridge returns
// a flat array of {context, offset, header} tables. The typed Go API
// returns []Reflection; the Lua shape uses the context's string name
// so the comparator on the Lua side matches the constants the user
// already sees.
type LuaReflection struct {
	Context string
	Offset  int
	Header  string
}

func FindReflectionsLua(body []byte, headers http.Header, token string) []LuaReflection {
	src := FindReflections(body, headers, token)
	out := make([]LuaReflection, 0, len(src))
	for _, r := range src {
		out = append(out, LuaReflection{Context: r.Context.String(), Offset: r.Offset, Header: r.Header})
	}
	return out
}
