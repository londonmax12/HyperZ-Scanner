package luabridge

import (
	"encoding/json"

	lua "github.com/yuin/gopher-lua"
)

// buildJSONTable returns the ctx.json helper namespace. Lua-authored
// checks need a JSON encoder to build operator-injection request bodies
// (nosqli) without re-implementing escaping rules per-check. Decoding
// is exposed for symmetry; both helpers thinly wrap encoding/json so
// the bridge surface stays narrow and the semantics match every other
// JSON consumer in the codebase.
//
// Helpers seeded here:
//
//	ctx.json.encode(value) -> string, err
//	  Marshals a Lua value into a JSON string. Lua tables are
//	  classified as arrays when the table has any integer keys
//	  starting at 1 and no string keys present; otherwise as objects.
//	  Mixed-key tables raise an error rather than silently dropping
//	  data, because the ambiguous shape is overwhelmingly a Lua bug
//	  the author wants to see.
//
//	ctx.json.decode(string) -> value, err
//	  Parses a JSON string into the corresponding Lua value. Objects
//	  become string-keyed tables; arrays become integer-keyed tables;
//	  nulls become Lua nil (so a key missing from a returned table is
//	  indistinguishable from a key explicitly set to null - the
//	  trade-off matches gopher-lua's other JSON shims).
func buildJSONTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("encode", L.NewFunction(jsonEncode))
	t.RawSetString("decode", L.NewFunction(jsonDecode))
	return t
}

func jsonEncode(L *lua.LState) int {
	v := L.Get(1)
	goValue, err := luaToGo(v)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	b, err := json.Marshal(goValue)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(string(b)))
	return 1
}

func jsonDecode(L *lua.LState) int {
	src := requireString(L, 1)
	var goValue any
	if err := json.Unmarshal([]byte(src), &goValue); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(goToLua(L, goValue))
	return 1
}

// luaToGo converts a Lua value into the matching Go any for json.Marshal.
// Tables that have any string key get marshalled as JSON objects; tables
// with only positive-integer keys (1..n contiguous) marshal as arrays.
// A table that mixes both shapes is an authoring mistake (the resulting
// JSON would have to drop one half), so we return an error rather than
// quietly producing surprising output.
func luaToGo(v lua.LValue) (any, error) {
	switch t := v.(type) {
	case *lua.LNilType:
		return nil, nil
	case lua.LBool:
		return bool(t), nil
	case lua.LNumber:
		return float64(t), nil
	case lua.LString:
		return string(t), nil
	case *lua.LTable:
		return luaTableToGo(t)
	}
	if v == nil || v == lua.LNil {
		return nil, nil
	}
	return v.String(), nil
}

func luaTableToGo(t *lua.LTable) (any, error) {
	arrayLen := t.Len()
	hasStringKey := false
	t.ForEach(func(k, _ lua.LValue) {
		if _, ok := k.(lua.LString); ok {
			hasStringKey = true
		}
	})
	switch {
	case arrayLen > 0 && hasStringKey:
		// Mixed shapes get raised rather than silently dropping data.
		// Authors writing JSON bodies by hand should hit this loudly
		// at the call site, not later on the wire.
		return nil, errString("json.encode: table mixes integer and string keys")
	case arrayLen > 0:
		arr := make([]any, 0, arrayLen)
		for i := 1; i <= arrayLen; i++ {
			converted, err := luaToGo(t.RawGetInt(i))
			if err != nil {
				return nil, err
			}
			arr = append(arr, converted)
		}
		return arr, nil
	}
	obj := map[string]any{}
	var conversionErr error
	t.ForEach(func(k, v lua.LValue) {
		if conversionErr != nil {
			return
		}
		name, ok := k.(lua.LString)
		if !ok {
			conversionErr = errString("json.encode: non-string object key")
			return
		}
		converted, err := luaToGo(v)
		if err != nil {
			conversionErr = err
			return
		}
		obj[string(name)] = converted
	})
	if conversionErr != nil {
		return nil, conversionErr
	}
	return obj, nil
}

// errString is the in-package error type the JSON encoder raises on
// authoring violations (mixed table shapes, non-string object keys).
// Keeping it local to the bridge avoids dragging fmt.Errorf into a
// path where the message is fixed.
type errString string

func (e errString) Error() string { return string(e) }

func goToLua(L *lua.LState, v any) lua.LValue {
	switch t := v.(type) {
	case nil:
		return lua.LNil
	case bool:
		return lua.LBool(t)
	case float64:
		return lua.LNumber(t)
	case string:
		return lua.LString(t)
	case []any:
		arr := L.NewTable()
		for i, item := range t {
			arr.RawSetInt(i+1, goToLua(L, item))
		}
		return arr
	case map[string]any:
		obj := L.NewTable()
		for k, item := range t {
			obj.RawSetString(k, goToLua(L, item))
		}
		return obj
	}
	return lua.LString(stringer(v))
}

func stringer(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
