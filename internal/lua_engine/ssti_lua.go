package lua_engine

import "strings"

// This file exposes the ssti check's helpers to the Lua bridge.
// Sibling to ssti.go: forwards into the package-private pattern
// catalogue, OOB-payload list, error-payload list, confirm-probe
// deriver, and the locDescriptor renderer so the Lua port runs the
// same sweep the Go check does.

// SSTIErrorNewMatches exposes the SSTI check's pattern catalogue
// against the Lua port's baseline + payload-stage subtraction.
func SSTIErrorNewMatches(body, baseline []byte) []string {
	return subtractPatterns(matchSSTIErrors(body), matchSSTIErrors(baseline))
}

func SSTIErrorPayloadsLua() []string {
	out := make([]string, len(sstiErrorPayloads))
	copy(out, sstiErrorPayloads)
	return out
}

// SSTIConfirmProbeLua returns the (template, expected) pair derived
// from the original probe by swapping the "7*7"/"49" operands for
// "8*9"/"72". A genuine SSTI evaluates the second probe in the same
// engine syntax; a passively-reflecting page cannot replay a fresh
// expression. Mirrors SSTI.confirmProbe verbatim.
func SSTIConfirmProbeLua(template string) (string, string) {
	return strings.Replace(template, "7*7", "8*9", 1), "72"
}

// SSTIOOBPayloadLua / SSTIOOBPayloadsLua mirror the cmd-injection-blind
// pair for SSTI. Each entry is one engine-specific blind probe; the
// Lua port substitutes {{URL}} with the canary URL on send. Engine
// rides as a field so the Drain pass can attribute the right engine
// name on a confirmed callback.
type SSTIOOBPayloadLua struct {
	Engine   string
	Template string
}

func SSTIOOBPayloadsLua() []SSTIOOBPayloadLua {
	out := make([]SSTIOOBPayloadLua, 0, len(sstiOOBPayloads))
	for _, p := range sstiOOBPayloads {
		out = append(out, SSTIOOBPayloadLua{Engine: p.Engine, Template: p.Tmpl})
	}
	return out
}

// LocDescriptorLua forwards the locDescriptor helper so the Lua port
// renders titles like "header" / "cookie" / "parameter" the same way
// the Go check does. Drops the need for a per-port lookup table.
func LocDescriptorLua(loc string) string { return locDescriptor(Loc(loc)) }
