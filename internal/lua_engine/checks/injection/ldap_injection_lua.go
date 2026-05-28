package injection

import (
	"github.com/londonmax12/hyperz/internal/lua_engine"
)

// This file exposes the ldap-injection check's helpers to the Lua
// bridge. Sibling to ldap_injection.go: forwards into the package-
// private pattern + payload sets so the Lua port owns only the per-
// sink orchestration.

// LDAPErrorNewMatches / LDAPiBooleanPairsLua / LDAPiErrorPayloadsLua
// expose the LDAPi check's private pattern + payload sets. The pattern
// catalogue and the matcher live in Go; the Lua port owns the per-sink
// orchestration only.
func LDAPErrorNewMatches(body, baseline []byte) []string {
	return lua_engine.SubtractPatterns(matchLDAPErrors(body), matchLDAPErrors(baseline))
}

// LDAPiBooleanProbePair carries one LDAPi truthy/falsy probe pair.
// FalsyTemplate carries the {{CANARY}} placeholder the Lua port
// substitutes per probe (one fresh canary per pair) before the
// suffix gets concatenated onto sink.Value.
type LDAPiBooleanProbePair struct {
	Name          string
	Truthy        string
	FalsyTemplate string
}

func LDAPiBooleanPairsLua() []LDAPiBooleanProbePair {
	out := make([]LDAPiBooleanProbePair, 0, len(ldapiBooleanPairs))
	for _, p := range ldapiBooleanPairs {
		out = append(out, LDAPiBooleanProbePair{Name: p.Name, Truthy: p.Truthy, FalsyTemplate: p.FalsyTpl})
	}
	return out
}

// LDAPiCanaryPlaceholder exposes the placeholder string the Lua port
// substitutes per probe. Lua-side authors call this rather than
// hard-coding "{{CANARY}}" so a future change to the placeholder lands
// once, in Go.
func LDAPiCanaryPlaceholder() string { return ldapiCanaryPlaceholder }

func LDAPiErrorPayloadsLua() []string {
	out := make([]string, len(ldapiErrorPayloads))
	copy(out, ldapiErrorPayloads)
	return out
}

// LDAPiSinkProbable forwards ldapiSinkProbable so the Lua port
// drops the same Loc set the Go check skips (header / cookie).
func LDAPiSinkProbable(loc string) bool {
	return ldapiSinkProbable(lua_engine.Sink{Loc: lua_engine.Loc(loc)})
}
