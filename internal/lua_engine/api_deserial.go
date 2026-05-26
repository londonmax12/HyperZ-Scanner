package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildDeserialTable returns the ctx.deserial helper namespace. The
// surface exposes the insecure-deserialization fingerprint catalogue
// + error-pattern matchers the Lua port reads; finding-shape
// composition lives in insecure_deserialization.lua.
//
// Entry points:
//
//	ctx.deserial.formats()
//	  Returns the format catalogue as an array of
//	  { name, label, probe_payload, error_pats } tables. The .lua port
//	  iterates this to drive the per-format probe sweep.
//
//	ctx.deserial.classify(value_string)
//	  Returns (name, label) for the first format whose fingerprint
//	  matches value_string, or ("", "") when no format matched. The
//	  passive arm calls this on cookie / query / form-input values.
//
//	ctx.deserial.match_all(body)
//	  Returns an array of every error pattern (across every format)
//	  present in body. The .lua port uses this as the baseline set.
//
//	ctx.deserial.match_format(body, format_name)
//	  Returns the subset of format_name's error patterns present in
//	  body. format_name is the slug surfaced by formats().
//
//	ctx.deserial.body_marker(body)
//	  Returns the human-readable label of the first deserialization
//	  fingerprint visible in body, or "" when none.
func buildDeserialTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("formats", L.NewFunction(deserialFormats))
	t.RawSetString("classify", L.NewFunction(deserialClassify))
	t.RawSetString("match_all", L.NewFunction(deserialMatchAll))
	t.RawSetString("match_format", L.NewFunction(deserialMatchFormat))
	t.RawSetString("body_marker", L.NewFunction(deserialBodyMarker))
	return t
}

func deserialFormats(L *lua.LState) int {
	out := L.NewTable()
	for i, f := range DeserialFormatListLua() {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(f.Name))
		entry.RawSetString("label", lua.LString(f.Label))
		entry.RawSetString("probe_payload", lua.LString(f.ProbePayload))
		entry.RawSetString("error_pats", pushStringList(L, f.ErrorPats))
		out.RawSetInt(i+1, entry)
	}
	L.Push(out)
	return 1
}

func deserialClassify(L *lua.LState) int {
	name, label := DeserialClassifyValueLua(requireString(L, 1))
	L.Push(lua.LString(name))
	L.Push(lua.LString(label))
	return 2
}

func deserialMatchAll(L *lua.LState) int {
	L.Push(pushStringList(L, DeserialMatchAllLua([]byte(requireString(L, 1)))))
	return 1
}

func deserialMatchFormat(L *lua.LState) int {
	body := requireString(L, 1)
	name := requireString(L, 2)
	L.Push(pushStringList(L, DeserialMatchFormatLua([]byte(body), name)))
	return 1
}

func deserialBodyMarker(L *lua.LState) int {
	L.Push(lua.LString(DeserialBodyMarkerLua([]byte(requireString(L, 1)))))
	return 1
}
