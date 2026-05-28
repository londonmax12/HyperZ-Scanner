// Package checks holds the Lua-authored check catalog. The catalog is
// organized into per-family subdirectories (injection, xss, headers,
// cors, ...) plus platform/<middleware>/ for protocol- and CMS-
// specific rules (platform/openapi, platform/oauth, platform/wordpress,
// ...). The Go side intentionally carries only this embed shim so
// every rule ships baked into a single binary while the detection
// logic itself stays in pure Lua. See internal/lua_engine for the
// loader, runtime, and bridge that turns these scripts into Check
// implementations.
//
// Subdirectory placement is organizational only - the loader walks the
// tree and the resulting registry is flat, keyed by each module's
// declared name (not its file path).
package checks

import "embed"

// Sources is the embedded *.lua catalog. internal/lua_engine.All
// walks this FS recursively to produce the registered Check set, so
// adding a new family folder here means listing it on the directive
// below.
//
//go:embed access concurrency cookies cors crypto discovery headers html injection platform smuggling supply_chain xss
var Sources embed.FS
