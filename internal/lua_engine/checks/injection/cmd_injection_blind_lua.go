package injection

import "strings"

// This file exposes the cmd-injection-blind check's helpers to the
// Lua bridge. Sibling to cmd_injection_blind.go: forwards into the
// package-private OOB payload list + shell-error pattern catalogue so
// the Lua port sweeps the same context-specific probes the Go check
// does.

// CmdErrorFirstMatch returns the first cmd-error pattern that appears
// in body, or "" when none does. Wraps the same case-insensitive scan
// the Go check uses inline so the Lua port consumes the result without
// re-shaping the catalogue.
func CmdErrorFirstMatch(body []byte) string {
	lower := strings.ToLower(string(body))
	for _, sig := range CmdErrorPatterns() {
		if strings.Contains(lower, sig) {
			return sig
		}
	}
	return ""
}

// CmdInjectionBlindOOBPayloadLua / CmdInjectionBlindOOBPayloadsLua
// expose the OOB-only payload list for the cmd-injection-blind check.
// Each entry is one canary-fetching shell-context template; the Lua
// port substitutes {{URL}} per probe with the canary URL the OOB
// listener minted.
type CmdInjectionBlindOOBPayloadLua struct {
	Name     string
	Template string
}

func CmdInjectionBlindOOBPayloadsLua() []CmdInjectionBlindOOBPayloadLua {
	out := make([]CmdInjectionBlindOOBPayloadLua, 0, len(cmdInjectionBlindOOBPayloads))
	for _, p := range cmdInjectionBlindOOBPayloads {
		out = append(out, CmdInjectionBlindOOBPayloadLua{Name: p.Name, Template: p.Tmpl})
	}
	return out
}
