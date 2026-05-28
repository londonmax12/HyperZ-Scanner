package xss

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// buildXSSTable returns the ctx.xss helper namespace. The surface is
// the reflected-xss / dom-xss / stored-xss family's body-scanning +
// payload-picking helpers, plus the curated XSS payload catalogue. The
// helpers used to live on the root ctx.body / ctx.payloads but are
// check-specific to the XSS family, so they moved with the Go files
// when the family was lifted into its own subpackage.
//
// Entry points:
//
//	ctx.xss.find_reflections(body, headers_userdata, token)
//	  -> [{context, offset, header}]
//
//	ctx.xss.xss_payloads_for_contexts(contexts, level)
//	  -> [{name, template}] (context-matched subset, level-aware)
//
//	ctx.xss.xss_context_summary(contexts)
//	  -> comma-separated dedup-ordered string of context names
//
//	ctx.xss.xss() -> [{name, template}] (the full XSS payload catalogue)
func buildXSSTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("find_reflections", L.NewFunction(xssFindReflections))
	t.RawSetString("xss_payloads_for_contexts", L.NewFunction(xssPayloadsForContexts))
	t.RawSetString("xss_context_summary", L.NewFunction(xssContextSummary))
	t.RawSetString("xss", L.NewFunction(xssPayloads))
	return t
}

// readStringList accepts a Lua string, an array table of strings, or
// nil, and returns the equivalent []string. Mirrors the root-level
// helper that used to back ctx.body.xss_payloads_for_contexts; lives
// here now that the helper does.
func readStringList(v lua.LValue) []string {
	if v == nil || v == lua.LNil {
		return nil
	}
	if s, ok := v.(lua.LString); ok {
		return []string{string(s)}
	}
	if tbl, ok := v.(*lua.LTable); ok {
		n := tbl.Len()
		out := make([]string, 0, n)
		for i := 1; i <= n; i++ {
			out = append(out, lua_engine.LValString(tbl.RawGetInt(i)))
		}
		return out
	}
	return nil
}

// xssFindReflections runs the HTML / JS state machine reflection
// scanner against body / headers and returns an array of
// {context, offset, header} tables. context is the string name of the
// matched Context (so a Lua-side comparator does not need to know the
// numeric enum). Header is "" for body matches.
func xssFindReflections(L *lua.LState) int {
	body := lua_engine.RequireString(L, 1)
	var headers http.Header
	if h, ok := lua_engine.UnwrapHeaders(L.Get(2)); ok {
		headers = h
	}
	token := lua_engine.RequireString(L, 3)
	hits := FindReflectionsLua([]byte(body), headers, token)
	out := L.NewTable()
	for i, r := range hits {
		entry := L.NewTable()
		entry.RawSetString("context", lua.LString(r.Context))
		entry.RawSetString("offset", lua.LNumber(r.Offset))
		entry.RawSetString("header", lua.LString(r.Header))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// xssPayloadsForContexts picks the context-matched XSS payload
// subset for the supplied reflection contexts (an array of context
// strings) at the active scan level. Returns an ordered array of
// {name, template} tables; mirrors the Go check's payloadsForContexts
// shape so the Lua port iterates payloads in the same order.
func xssPayloadsForContexts(L *lua.LState) int {
	contexts := readStringList(L.Get(1))
	level := lua_engine.OptString(L, 2, "default")
	src := XSSPayloadsForContextsLua(contexts, level)
	return lua_engine.PushPayloadList(L, src)
}

func xssContextSummary(L *lua.LState) int {
	contexts := readStringList(L.Get(1))
	L.Push(lua.LString(XSSContextSummaryLua(contexts)))
	return 1
}

// xssPayloads returns the full XSS payload catalogue as an array of
// {name, template} tables. Mirrors the root-level ctx.payloads.xss
// helper the rest of the bridge exposes for the other payload
// families.
func xssPayloads(L *lua.LState) int {
	return lua_engine.PushPayloadList(L, lua_engine.XSSPayloadsLua())
}

func init() {
	lua_engine.RegisterHelperTable("xss", buildXSSTable)
}
