package luabridge

import (
	lua "github.com/yuin/gopher-lua"

	"github.com/londonmax12/hyperz/internal/checks"
)

// buildTakeoverTable returns the ctx.takeover helper namespace. The
// single entry point - evaluate(page_url) - runs the two-path probe
// (CNAME-confirmed and fingerprint-only) and returns the raw scan
// FACTS, not a finding shape: provider name + per-provider guidance
// string, detection path, CNAME (when applicable), probe URL, probe
// status, body preview, and the provider-identifying response headers
// that matched.
//
// All operator-visible catalog metadata (title, severity, detail,
// details, CWE, OWASP, remediation, dedupe key, evidence) is composed
// by the .lua port from those facts. The probe / DNS / fingerprint
// algorithm stays in Go on a *checks.SubdomainTakeover that lives on
// the LuaCheck instance (see takeoverEvaluatorKey), so per-host work
// is done at most once per scan and the cache lifetime mirrors the Go
// check's `&checks.SubdomainTakeover{}` registration lifetime.
func buildTakeoverTable(L *lua.LState) *lua.LTable {
	t := L.NewTable()
	t.RawSetString("evaluate", L.NewFunction(takeoverEvaluate))
	return t
}

// takeoverEvaluatorKey identifies this helper's slot in the LuaCheck
// aux map. Unique zero-size type so two helpers can never collide on
// key equality and so the value goes through type assertion cleanly.
type takeoverEvaluatorKey struct{}

// takeoverEvaluate implements ctx.takeover.evaluate(page_url).
//
// Returns nil when the host is clean (and no error to report); returns
// a table of raw scan facts when a takeover signal is detected. On a
// transient probe failure the function returns (nil, err_string) which
// the Lua port surfaces via ctx:report rather than re-raising.
//
// Facts table shape:
//
//	{
//	  provider          = "GitHub Pages",
//	  provider_guidance = "Register the GitHub Pages site under the GitHub account you control ...",
//	  detection         = "cname" | "fingerprint",
//	  cname             = "abandoned-user.github.io",   -- "" on fingerprint path
//	  dns_note          = "CNAME target resolves to NXDOMAIN; ...", -- "" when none
//	  probe_url         = "https://host.example.com/",
//	  status            = 404,                            -- 0 when probe was skipped (NXDOMAIN-only path)
//	  body_preview      = "There isn't a GitHub Pages site here.", -- capped to 512 bytes
//	  matched_headers   = { { name = "Server", value = "GitHub.com" }, ... }, -- fingerprint path only
//	}
//
// The .lua port reads these fields and constructs every finding-shape
// catalog field itself (title, severity, detail, details, CWE, OWASP,
// remediation, dedupe key, evidence). Keeping the bridge return as raw
// facts is intentional: the rule lives in Lua, the scanner algorithm
// lives in Go.
func takeoverEvaluate(L *lua.LState) int {
	env := currentEnv(L)
	if env == nil {
		L.RaiseError("ctx.takeover.evaluate called outside a check run")
	}
	pageURL := requireString(L, 1)
	eval := env.check.AuxOrCreate(takeoverEvaluatorKey{}, func() any {
		return &checks.SubdomainTakeover{}
	}).(*checks.SubdomainTakeover)
	facts, err := eval.FactsFor(env.ctx, env.client, env.scope, pageURL)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	if facts == nil {
		L.Push(lua.LNil)
		return 1
	}

	out := L.NewTable()
	out.RawSetString("provider", lua.LString(facts.Provider))
	out.RawSetString("provider_guidance", lua.LString(facts.ProviderGuidance))
	out.RawSetString("detection", lua.LString(facts.Detection))
	out.RawSetString("cname", lua.LString(facts.CNAME))
	out.RawSetString("dns_note", lua.LString(facts.DNSNote))
	out.RawSetString("probe_url", lua.LString(facts.ProbeURL))
	out.RawSetString("status", lua.LNumber(facts.Status))
	out.RawSetString("body_preview", lua.LString(facts.BodyPreview))

	headers := L.NewTable()
	for i, hit := range facts.MatchedHeaders {
		entry := L.NewTable()
		entry.RawSetString("name", lua.LString(hit.Name))
		entry.RawSetString("value", lua.LString(hit.Value))
		headers.RawSetInt(i+1, entry)
	}
	out.RawSetString("matched_headers", headers)

	L.Push(out)
	return 1
}
