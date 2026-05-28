package lua_engine

// This file exposes the sqli-error check's helpers to the Lua bridge.
// Sibling to sqli_error.go: forwards into the package-private SQL
// pattern matcher so the Lua port consumes the same catalogue the Go
// check sweeps.

// SQLiErrorNewMatches returns the SQL-driver error patterns that
// appear in body but did not appear in baseline. The pattern catalogue
// lives in Go (sqli_error.go's SQLErrorPatterns); the Lua port owns
// the orchestration (baseline send, per-payload probe, finding shape).
// Each result is the matched pattern name so the Lua side can stamp
// it into the per-finding detail.
func SQLiErrorNewMatches(body, baseline []byte) []string {
	return subtractPatterns(matchSQLPatterns(body), matchSQLPatterns(baseline))
}
