package lua_engine

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

// newVM builds a sandboxed *lua.LState. SkipOpenLibs prevents the
// default libraries from auto-opening; openSafeLibs then selectively
// opens the subset a check author legitimately needs (base for control
// flow + tostring/ipairs/etc., table, string, math). os, io, package,
// debug, and the file loaders stay closed so a malicious or buggy
// check can not touch the host filesystem, spawn processes, or load
// arbitrary .lua files outside the embedded set.
//
// require is stripped from the base library after open so even a
// poisoned package.path can not reach it. dofile / loadfile / load /
// loadstring are stripped for the same reason: every Lua source the
// scanner runs goes through Load, where the compiled FunctionProto is
// captured up front and cached.
func newVM() *lua.LState {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	openSafeLibs(L)
	stripUnsafeBaseFns(L)
	bindHyperzAPI(L)
	return L
}

// safeLibs is the closed set of standard libraries every Lua check is
// allowed to use. base supplies the language primitives (assert, error,
// ipairs, pairs, pcall, select, tonumber, tostring, type, unpack);
// table/string/math give the data-manipulation utilities checks
// actually need. Adding more here is a deliberate capability decision -
// each entry widens what a third-party rule pack can do.
var safeLibs = []struct {
	name string
	fn   lua.LGFunction
}{
	{lua.LoadLibName, lua.OpenPackage}, // opened then immediately neutered (see below)
	{lua.BaseLibName, lua.OpenBase},
	{lua.TabLibName, lua.OpenTable},
	{lua.StringLibName, lua.OpenString},
	{lua.MathLibName, lua.OpenMath},
}

func openSafeLibs(L *lua.LState) {
	for _, lib := range safeLibs {
		L.Push(L.NewFunction(lib.fn))
		L.Push(lua.LString(lib.name))
		L.Call(1, 0)
	}
	// Neuter the package library so an author can not redirect require
	// at runtime. We opened it only because gopher-lua's compiled-chunk
	// loader expects the `package` global to exist; with searchers
	// emptied and loaded cleared it can not be used to import code.
	if pkg, ok := L.GetGlobal("package").(*lua.LTable); ok {
		pkg.RawSetString("loaders", L.NewTable())
		pkg.RawSetString("searchers", L.NewTable())
		pkg.RawSetString("loaded", L.NewTable())
		pkg.RawSetString("preload", L.NewTable())
		pkg.RawSetString("path", lua.LString(""))
		pkg.RawSetString("cpath", lua.LString(""))
	}
}

// unsafeBaseFns are removed from the base library after open. Each is
// either a code-loader (lets the check import arbitrary Lua source
// from disk or strings) or a host-introspection escape (collectgarbage
// can drive denial-of-service via forced sweeps). Stripping them keeps
// the sandbox honest even if a check is hostile.
var unsafeBaseFns = []string{
	"dofile",
	"loadfile",
	"load",
	"loadstring",
	"require",
	"collectgarbage",
	"newproxy",
}

func stripUnsafeBaseFns(L *lua.LState) {
	for _, name := range unsafeBaseFns {
		L.SetGlobal(name, lua.LNil)
	}
}

// instantiateModule runs proto inside L and returns the top-of-stack
// value (the check module table). It returns an error if the module
// did not return a table - every Lua check is required to end with
// `return check`, so anything else is a malformed source.
func instantiateModule(L *lua.LState, proto *lua.FunctionProto) (*lua.LTable, error) {
	fn := L.NewFunctionFromProto(proto)
	L.Push(fn)
	if err := L.PCall(0, 1, nil); err != nil {
		return nil, fmt.Errorf("lua module init: %w", err)
	}
	v := L.Get(-1)
	L.Pop(1)
	tbl, ok := v.(*lua.LTable)
	if !ok {
		return nil, fmt.Errorf("lua module did not return a table (got %s)", v.Type())
	}
	return tbl, nil
}
