// Package checks_lua embeds the Lua-authored check catalog and
// exposes a single All() entry point that the cmd/hyperz registry
// calls during startup.
//
// Lua sources live alongside this file (one .lua per check) and are
// baked into the binary via go:embed so distribution stays single-
// binary. Add a new file and it is picked up automatically; nothing
// in cmd/hyperz needs to change as the Lua catalog grows.
//
// Load failure (parse error, malformed module metadata) panics on
// startup: a misauthored rule the binary won't even start with is
// strictly better than a binary that boots and silently runs without
// the broken check. Catalog hygiene is enforced by the build / CI,
// not at runtime in front of an operator scanning their target.
package checks_lua

import (
	"embed"
	"fmt"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/luabridge"
)

//go:embed *.lua
var sources embed.FS

// All returns every Lua-authored check in the embedded catalog.
// Order is deterministic (alphabetical by filename) so the
// downstream `hyperz checks list` output stays stable across builds.
func All() []checks.Check {
	loaded, err := luabridge.LoadDir(sources, ".")
	if err != nil {
		panic(fmt.Errorf("checks_lua: %w", err))
	}
	return luabridge.AsChecks(loaded)
}
