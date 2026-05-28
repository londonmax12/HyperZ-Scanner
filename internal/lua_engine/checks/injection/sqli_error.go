package injection

// This file used to host the SQLi pattern matcher + subtract helper,
// but both are cross-family utilities (the JWT alg-confusion check
// reuses them to recognise SQL driver leakage in confused-key probe
// responses), so they moved back into lua_engine root as
// MatchSQLPatterns / SubtractPatterns when the injection family was
// lifted into its own subpackage. The sqli-error per-check wiring
// lives in sqli_error_lua.go alongside the other check-local helpers.
