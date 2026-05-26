package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// buildDeserialTable returns the ctx.deserial helper namespace. The
// surface exposes the insecure-deserialization fingerprint catalogue
// + error-pattern matchers the Lua port reads; finding-shape
// composition lives in insecure_deserialization.lua.
//
// Four of the five entries take a catalogue name as their first
// argument so a future check that registers its own format set
// (vendor-specific serializers, RPC envelopes) can scope its sweep
// without affecting the canonical "http_body" catalogue. body_marker
// stays catalogue-independent because its marker set is a fixed list
// of base64 / text prefixes, not derived from the format list.
//
// Entry points:
//
//	ctx.deserial.formats(catalogue)
//	  Returns the named catalogue's format list as an array of
//	  { name, label, probe_payload, error_pats } tables. The .lua port
//	  iterates this to drive the per-format probe sweep.
//
//	ctx.deserial.classify(catalogue, value_string)
//	  Returns (name, label) for the first format in catalogue whose
//	  fingerprint matches value_string, or ("", "") when no format
//	  matched. The passive arm calls this on cookie / query / form-
//	  input values.
//
//	ctx.deserial.match_all(catalogue, body)
//	  Returns an array of every error pattern (across every format
//	  in catalogue) present in body. The .lua port uses this as the
//	  baseline set.
//
//	ctx.deserial.match_format(catalogue, body, format_name)
//	  Returns the subset of format_name's error patterns present in
//	  body. catalogue picks the format set format_name is looked up
//	  in; format_name is the slug surfaced by formats().
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
	catalogue := requireString(L, 1)
	out := L.NewTable()
	for i, f := range DeserialFormatListLua(catalogue) {
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
	catalogue := requireString(L, 1)
	name, label := DeserialClassifyValueLua(catalogue, requireString(L, 2))
	L.Push(lua.LString(name))
	L.Push(lua.LString(label))
	return 2
}

func deserialMatchAll(L *lua.LState) int {
	catalogue := requireString(L, 1)
	body := requireString(L, 2)
	L.Push(pushStringList(L, DeserialMatchAllLua(catalogue, []byte(body))))
	return 1
}

func deserialMatchFormat(L *lua.LState) int {
	catalogue := requireString(L, 1)
	body := requireString(L, 2)
	name := requireString(L, 3)
	L.Push(pushStringList(L, DeserialMatchFormatLua(catalogue, []byte(body), name)))
	return 1
}

func deserialBodyMarker(L *lua.LState) int {
	L.Push(lua.LString(DeserialBodyMarkerLua([]byte(requireString(L, 1)))))
	return 1
}
