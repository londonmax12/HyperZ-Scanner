package checks

// IDORVerdict is the exported view of the IDOR oracle's per-probe
// decision. The Lua bridge reads it through IDORJudge; keeping the
// Lua-visible shape exported keeps the bridge from reaching into
// the package-private idorVerdict type via reflection or back-
// channels. Field semantics are the same as the private mirror;
// see idorJudge for the algorithm.
type IDORVerdict struct {
	Vulnerable         bool
	Confidence         string
	Detail             string
	TamperedSim        float64
	ControlSim         float64
	TamperedControlSim float64
	PIIHints           []string
}

// IDORJudge wraps the package-private idorJudge so the Lua bridge
// can call it without re-implementing the verdict logic. Returning
// the exported IDORVerdict mirror keeps the bridge ABI stable when
// the private idorVerdict gains internal-only fields.
func IDORJudge(baseline, tampered, control Snapshot) IDORVerdict {
	v := idorJudge(baseline, tampered, control)
	return IDORVerdict{
		Vulnerable:         v.Vulnerable,
		Confidence:         v.Confidence,
		Detail:             v.Detail,
		TamperedSim:        v.TamperedSim,
		ControlSim:         v.ControlSim,
		TamperedControlSim: v.TamperedControlSim,
		PIIHints:           v.PIIHints,
	}
}

// IDORControlPayload wraps controlPayloadFor so the Lua bridge can
// pick the same sentinel garbage value the Go check uses for a given
// (pattern, seed). Identical mapping keeps the two impls' dedupe
// keys and false-positive backstops aligned on the same wire.
func IDORControlPayload(p *Pattern, seed string) string {
	return controlPayloadFor(p, seed)
}

// BuiltinPatterns returns a clone of the engine's built-in identifier
// patterns. Exposed as a Corpus method so the Lua bridge can resolve
// a pattern name to its *Pattern (for Generate) without depending on
// a package-private slice. The Learned patterns slice on the same
// Corpus is already public via LearnedPatterns.
func (c *Corpus) BuiltinPatterns() []Pattern {
	out := make([]Pattern, len(builtinPatterns))
	copy(out, builtinPatterns)
	return out
}
