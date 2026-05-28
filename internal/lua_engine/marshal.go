package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// lvalString coerces v to a Go string. Lua-side authors freely mix
// `nil`, strings, and tostring-able values; passing a non-string
// through this helper yields "" rather than a runtime error, because
// metadata fields are mostly optional and we'd rather quietly fall
// back to the default than reject the whole module for a typo.
//
// Use this for free-form metadata (cwe, title, detail). For inputs
// that must be a string (a header name, a redirect URL), prefer
// RequireString so the bridge surfaces a useful argument-position
// error.
func lvalString(v lua.LValue) string {
	if v == nil || v == lua.LNil {
		return ""
	}
	if s, ok := v.(lua.LString); ok {
		return string(s)
	}
	return v.String()
}

// lvalInt coerces v to a Go int. Non-numbers (nil, strings,
// userdata) collapse to 0. Like lvalString, this is for optional
// fields where 0/missing is benign; required numeric arguments
// should use L.CheckInt(n) instead.
func lvalInt(v lua.LValue) int {
	if n, ok := v.(lua.LNumber); ok {
		return int(n)
	}
	return 0
}

// lvalBool coerces v to a Go bool with Lua's truthiness rules: only
// `nil` and `false` are false; everything else (including 0, "", and
// the empty table) is true. Matches how a check author would test
// the value with `if v then ... end`.
func lvalBool(v lua.LValue) bool {
	return lua.LVAsBool(v)
}

// RequireString returns the string value at stack position pos or
// raises a Lua argument error. Use at the entry of every Lua-callable
// Go function that needs a non-empty string argument; the resulting
// error surfaces in the running check's runErr return rather than as
// a Go panic.
func RequireString(L *lua.LState, pos int) string {
	v := L.Get(pos)
	if s, ok := v.(lua.LString); ok {
		return string(s)
	}
	L.RaiseError("argument #%d: expected string, got %s", pos, v.Type())
	return ""
}

// optString returns the string at pos or fallback if pos is absent or
// nil. Distinct from RequireString in that a missing argument is
// allowed - useful for optional flags like dedupe scope overrides.
func optString(L *lua.LState, pos int, fallback string) string {
	v := L.Get(pos)
	if v == lua.LNil {
		return fallback
	}
	if s, ok := v.(lua.LString); ok {
		return string(s)
	}
	return fallback
}

// stringList reads an array-style Lua table at t[name] and returns its
// values as a Go []string. Non-string entries are coerced via
// lvalString (so a numeric dedupe part still serializes deterministically);
// missing field or non-table value returns nil.
func stringList(t *lua.LTable, name string) []string {
	v := t.RawGetString(name)
	tbl, ok := v.(*lua.LTable)
	if !ok {
		return nil
	}
	n := tbl.Len()
	if n <= 0 {
		return nil
	}
	out := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, lvalString(tbl.RawGetInt(i)))
	}
	return out
}

// PushStringList returns a 1-indexed Lua array table built from strs.
// Bridge surfaces that hand a Go []string back to a .lua port call
// this so the per-bridge file does not open-code the
// `RawSetInt(i+1, lua.LString(s))` loop. Returns an empty table when
// strs is nil or zero-length, matching what the inline loops produced.
func PushStringList(L *lua.LState, strs []string) *lua.LTable {
	t := L.NewTable()
	for i, s := range strs {
		t.RawSetInt(i+1, lua.LString(s))
	}
	return t
}

