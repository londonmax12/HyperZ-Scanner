package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildHTMLTable returns the ctx.html helper table. The helpers wrap
// the Go-side golang.org/x/net/html tokenizer so a Lua check that
// walks an HTML body does not have to re-implement tokenization in
// Lua patterns. Two surfaces are exposed:
//
//	ctx.html.iter_tags(body, tag_set)
//	  -> array of { tag = "...", attrs = [{name=..., value=...}, ...],
//	                attr = { name = value, ... } }
//	     tag_set is an array of lower-cased tag names; nil means "all".
//	     `attrs` preserves order (browsers take the first duplicate),
//	     `attr` is a name -> first-value convenience for the common case.
//
//	ctx.html.resolve_ref(base_url, ref)
//	  -> (string, true) | (nil, false) for skip-shapes (javascript:,
//	     data:, fragment, ...). The skip set is the one IterHTMLTags's
//	     Go-side ResolveURLRef enforces so the per-port skip lists stay
//	     consistent.
//
// Both helpers are pure functions of their input; like the rest of
// the static helpers they are built once per VM and snapped into each
// per-Run ctx by buildCtxUserdata.
func buildHTMLTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("iter_tags", L.NewFunction(htmlIterTags))
	t.RawSetString("resolve_ref", L.NewFunction(htmlResolveRef))
	t.RawSetString("scan_form_actions", L.NewFunction(htmlScanFormActions))
	return t
}

// htmlIterTags implements ctx.html.iter_tags. Reads the body string +
// optional tag-set array, delegates to IterHTMLTags, and
// converts the result into Lua tables.
func htmlIterTags(L *lua.LState) int {
	body := requireString(L, 1)
	var interesting map[string]bool
	if tbl, ok := L.Get(2).(*lua.LTable); ok {
		n := tbl.Len()
		interesting = make(map[string]bool, n)
		for i := 1; i <= n; i++ {
			interesting[lvalString(tbl.RawGetInt(i))] = true
		}
	}
	tags := IterHTMLTags([]byte(body), interesting)
	out := L.NewTable()
	for i, tg := range tags {
		entry := L.NewTable()
		entry.RawSetString("tag", lua.LString(tg.Name))
		// `attrs` keeps the ordered list - some callers care about
		// duplicates and the browser-first-wins rule.
		attrs := L.NewTable()
		// `attr` is the name -> first-value convenience map most ports
		// actually use; the ordered list is kept alongside for the rare
		// duplicate-attribute case.
		attrMap := L.NewTable()
		seen := map[string]bool{}
		for j, a := range tg.Attrs {
			ar := L.NewTable()
			ar.RawSetString("name", lua.LString(a.Name))
			ar.RawSetString("value", lua.LString(a.Value))
			attrs.RawSetInt(j+1, ar)
			if !seen[a.Name] {
				attrMap.RawSetString(a.Name, lua.LString(a.Value))
				seen[a.Name] = true
			}
		}
		entry.RawSetString("attrs", attrs)
		entry.RawSetString("attr", attrMap)
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// htmlScanFormActions implements ctx.html.scan_form_actions(body,
// base_url). Returns an array of candidate tables, one per
// (form action, override) pair the document carries:
//
//	{ raw, resolved, method, override, has_credential_field,
//	  inputs = [{name, type, sensitive}, ...] }
//
// Non-network actions (javascript:, mailto:, fragment) are filtered
// out on the Go side so the Lua port only sees candidates worth a
// scheme inspection. The form-action-insecure port consumes this
// directly and only owns the http:// branch decision + finding shape.
func htmlScanFormActions(L *lua.LState) int {
	body := requireString(L, 1)
	base := requireString(L, 2)
	cands := ScanFormActions([]byte(body), base)
	out := L.NewTable()
	for i, c := range cands {
		entry := L.NewTable()
		entry.RawSetString("raw", lua.LString(c.Raw))
		entry.RawSetString("resolved", lua.LString(c.Resolved))
		entry.RawSetString("method", lua.LString(c.Method))
		entry.RawSetString("override", lua.LBool(c.Override))
		entry.RawSetString("has_credential_field", lua.LBool(c.HasCredentialField))
		inputs := L.NewTable()
		for j, in := range c.Inputs {
			it := L.NewTable()
			it.RawSetString("name", lua.LString(in.Name))
			it.RawSetString("type", lua.LString(in.Type))
			it.RawSetString("sensitive", lua.LBool(in.Sensitive))
			inputs.RawSetInt(j+1, it)
		}
		entry.RawSetString("inputs", inputs)
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

// htmlResolveRef implements ctx.html.resolve_ref(base, ref). Returns
// (resolved_url_string, true) on success or (nil, false) for skip
// shapes; the boolean second return matches the Go helper's ok return
// so Lua-side `if ok then ... end` reads naturally.
func htmlResolveRef(L *lua.LState) int {
	base := requireString(L, 1)
	ref := requireString(L, 2)
	resolved, ok := ResolveURLRef(base, ref)
	if !ok {
		L.Push(lua.LNil)
		L.Push(lua.LBool(false))
		return 2
	}
	L.Push(lua.LString(resolved.String()))
	L.Push(lua.LBool(true))
	return 2
}

func init() {
	registerHelperTable("html", buildHTMLTable)
}
