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
// settings carries operator-supplied per-check config bags from the
// YAML config file, keyed by check name. Each kept check has its bag
// attached so the Lua side sees it via `ctx.config`; an unknown key
// (no matching check name) is returned via unknownSettings rather
// than failing the load - a config written for a newer build should
// still bring up an older one.
//
// Load failure (parse error, malformed module metadata) panics on
// startup: a misauthored rule the binary won't even start with is
// strictly better than a binary that boots and silently runs without
// the broken check. Catalog hygiene is enforced by the build / CI,
// not at runtime in front of an operator scanning their target.
func All(pollute bool, settings map[string]map[string]any) (checks_ []core.Check, unknownSettings []string) {
	loaded, err := LoadDir(checks.Sources, ".")
	if err != nil {
		panic(fmt.Errorf("lua_engine: %w", err))
	}
	known := map[string]bool{}
	kept := make([]*LuaCheck, 0, len(loaded))
	for _, c := range loaded {
		known[c.name] = true
		if c.pollute && !pollute {
			continue
		}
		if bag, ok := settings[c.name]; ok {
			c.SetSettings(bag)
		}
		kept = append(kept, c)
	}
	for name := range settings {
		if !known[name] {
			unknownSettings = append(unknownSettings, name)
		}
	}
	return AsChecks(kept), unknownSettings
}
