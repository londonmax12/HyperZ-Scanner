// Package checks holds the Lua-authored check catalog: one .lua file
// per rule. The Go side intentionally carries only this embed shim so
// every rule ships baked into a single binary while the detection
// logic itself stays in pure Lua. See internal/lua_engine for the
// loader, runtime, and bridge that turns these scripts into Check
// implementations.
package checks

import "embed"

// Sources is the embedded *.lua catalog. internal/lua_engine.All
// walks this FS to produce the registered Check set.
//
//go:embed *.lua
var Sources embed.FS
