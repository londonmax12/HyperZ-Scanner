package injection

import (
	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// This file exposes the sqli-error check's helpers to the Lua bridge.
// Forwards into the bridge-root SQL pattern matcher so the Lua port
// consumes the same catalogue the Go check sweeps.

// SQLiErrorNewMatches returns the SQL-driver error patterns that
// appear in body but did not appear in baseline. The pattern catalogue
// lives in Go (lua_engine.SQLErrorPatterns); the Lua port owns the
// orchestration (baseline send, per-payload probe, finding shape).
// Each result is the matched pattern name so the Lua side can stamp
// it into the per-finding detail.
func SQLiErrorNewMatches(body, baseline []byte) []string {
	return lua_engine.SubtractPatterns(
		lua_engine.MatchSQLPatterns(body),
		lua_engine.MatchSQLPatterns(baseline),
	)
}
