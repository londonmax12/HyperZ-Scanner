// Package lua_engine embeds a sandboxed Lua 5.1 runtime so individual
// hyperz checks can be authored as small Lua modules instead of full
// Go files. The Go engine retains every helper (HTTP client, sink
// inventory, OOB server, browser pool, fingerprint, payload library,
// snippet/oracle/snapshot/reflection utilities, regex-heavy body
// scanners): Lua only composes those primitives. That keeps performance
// where it matters (Go) and puts authoring ergonomics where it helps
// most (Lua), without forcing rule authors to learn Go.
//
// A Lua check is a table-style module:
//
//	-- internal/checks/server_leak.lua
//	local check = {
//	  name        = "server-leak",
//	  level       = "passive",
//	  scope       = "host",
//	  cwe         = "CWE-200",
//	  owasp       = "A05:2021 Security Misconfiguration",
//	  remediation = "Suppress or generalize the leaking header at the proxy.",
//	}
//
//	function check.run(ctx)
//	  local snap, err = ctx:ensure_response()
//	  if err then return nil, err end
//	  ...
//	  return findings   -- list of finding tables
//	end
//
//	return check
//
// The module is loaded once (Load) and the compiled FunctionProto is
// reused across a sync.Pool of *lua.LState values so concurrent Run
// calls from different goroutines do not share VM state. gopher-lua
// LStates are NOT goroutine-safe; the pool is what makes Lua checks
// safe to run inside the scanner's worker fanout.
//
// Capability sandbox: standard Lua libraries that touch the host
// (os, io, package, debug) are NOT opened. require is removed. Only
// the safe subset (base minus dofile/loadfile/load, table, string,
// math) is exposed alongside the hyperz bridge API.
package lua_engine
