package lua_engine

import (
	"fmt"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/core"
)

// All returns every Lua-authored check in the embedded catalog.
// Order is deterministic (alphabetical by filename) so the downstream
// `hyperz checks list` output stays stable across builds.
//
// pollute gates the disruptive / state-mutating subset (stored XSS
// plants, JWT brute-force, raw-socket smuggling probes, race-condition
// fan-out, prototype pollution). When pollute is false, modules that
// declared `pollute = true` in their metadata table are filtered out
// so a default scan stays read-only; pass true once the operator has
// opted in via --pollute at scan time.
//
// Load failure (parse error, malformed module metadata) panics on
// startup: a misauthored rule the binary won't even start with is
// strictly better than a binary that boots and silently runs without
// the broken check. Catalog hygiene is enforced by the build / CI,
// not at runtime in front of an operator scanning their target.
func All(pollute bool) []core.Check {
	loaded, err := LoadDir(checks.Sources, ".")
	if err != nil {
		panic(fmt.Errorf("lua_engine: %w", err))
	}
	kept := make([]*LuaCheck, 0, len(loaded))
	for _, c := range loaded {
		if c.pollute && !pollute {
			continue
		}
		kept = append(kept, c)
	}
	return AsChecks(kept)
}
