package xss

import (
	"net/http"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// This file exposes the reflected-xss check's helpers to the Lua
// bridge. Sibling to reflected_xss.go (and reflection.go): forwards
// into the package-private payload selector + context summary so the
// Lua port picks the same context-matched payload subset and renders
// the same summary the Go check does.

// XSSPayloadsForContextsLua exposes payloadsForContexts so the Lua
// reflected-xss port picks the same context-matched payload subset
// (deduped, source-ordered) the Go check uses. Reflections arrive as
// the context-string slice the bridge already exposes via
// lua_engine.FindReflections.
func XSSPayloadsForContextsLua(contexts []string, level string) []lua_engine.SQLiErrorPayload {
	parsedLevel, err := lua_engine.ParseLevel(level)
	if err != nil {
		parsedLevel = lua_engine.LevelDefault
	}
	refs := make([]lua_engine.Reflection, 0, len(contexts))
	for _, name := range contexts {
		refs = append(refs, lua_engine.Reflection{Context: contextFromString(name)})
	}
	picked := payloadsForContexts(refs, parsedLevel)
	out := make([]lua_engine.SQLiErrorPayload, 0, len(picked))
	for _, p := range picked {
		out = append(out, lua_engine.SQLiErrorPayload{Name: p.Name, Template: p.Template})
	}
	return out
}

// XSSContextSummaryLua returns the comma-separated, dedup-ordered list
// of context names from contexts. Mirrors contextSummary.
func XSSContextSummaryLua(contexts []string) string {
	refs := make([]lua_engine.Reflection, 0, len(contexts))
	for _, name := range contexts {
		refs = append(refs, lua_engine.Reflection{Context: contextFromString(name)})
	}
	return contextSummary(refs)
}

// contextFromString is the inverse of lua_engine.Context.String. Used
// by the Lua bridge to round-trip context strings back into the typed
// enum so the payload selector + summary functions get the same values
// lua_engine.FindReflections produced.
func contextFromString(name string) lua_engine.Context {
	switch name {
	case "header-value":
		return lua_engine.CtxHeaderValue
	case "html-text":
		return lua_engine.CtxHTMLText
	case "html-comment":
		return lua_engine.CtxHTMLComment
	case "attr-double-quoted":
		return lua_engine.CtxAttrDoubleQuoted
	case "attr-single-quoted":
		return lua_engine.CtxAttrSingleQuoted
	case "attr-unquoted":
		return lua_engine.CtxAttrUnquoted
	case "script-text":
		return lua_engine.CtxScriptText
	case "script-string-double":
		return lua_engine.CtxScriptStringDouble
	case "script-string-single":
		return lua_engine.CtxScriptStringSingle
	}
	return lua_engine.CtxNone
}

// FindReflectionsLua wraps lua_engine.FindReflections so the Lua bridge
// returns a flat array of {context, offset, header} tables. The typed
// Go API returns []lua_engine.Reflection; the Lua shape uses the
// context's string name so the comparator on the Lua side matches the
// constants the user already sees.
type LuaReflection struct {
	Context string
	Offset  int
	Header  string
}

func FindReflectionsLua(body []byte, headers http.Header, token string) []LuaReflection {
	src := lua_engine.FindReflections(body, headers, token)
	out := make([]LuaReflection, 0, len(src))
	for _, r := range src {
		out = append(out, LuaReflection{Context: r.Context.String(), Offset: r.Offset, Header: r.Header})
	}
	return out
}
