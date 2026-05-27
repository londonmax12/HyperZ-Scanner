package fingerprint

import "strings"

// AppliesSpec declares per-field allow-lists a check uses to gate
// itself against a detected Stack. It is the structured form behind a
// .lua check's `applies_to` table:
//
//	applies_to = { cms = {"wordpress"}, server = {"nginx", "apache"} }
//
// The semantic operators have been asking for is:
//
//   - Empty allow-list for a field = no constraint on that axis
//     (the spec is permissive there).
//   - Populated allow-list = the host's detected value for that field
//     must be in the allow-list, case-insensitive.
//   - Multiple populated fields AND together: every constrained field
//     must independently match.
//   - An unknown value (the stack left the field empty) passes every
//     constraint - we suppress on positive disagreement, not on
//     absence of evidence. This matches the discoveryEntry.appliesTo
//     contract that .lua content-discovery entries already use.
//
// A zero-value AppliesSpec is fully permissive (every host passes);
// checks that do not declare `applies_to` get this default.
type AppliesSpec struct {
	Server    []string
	Language  []string
	Framework []string
	CMS       []string
	CDN       []string
	WAF       []string
}

// IsEmpty reports whether the spec carries no constraints (every
// allow-list is empty). Used by callers that want to short-circuit
// gating logic before calling Matches; semantically equivalent to
// "Matches always returns true."
func (s AppliesSpec) IsEmpty() bool {
	return len(s.Server) == 0 &&
		len(s.Language) == 0 &&
		len(s.Framework) == 0 &&
		len(s.CMS) == 0 &&
		len(s.CDN) == 0 &&
		len(s.WAF) == 0
}

// Matches reports whether stack satisfies the spec. A nil stack means
// "no fingerprint available" and Matches returns true so a flaky
// fingerprint detection does not silently disable a check the operator
// expected to run. An empty spec also returns true.
//
// When stack is non-nil and the spec has constraints, every populated
// allow-list must pass; an empty value on the stack for a constrained
// field also passes ("unknown" is permissive, mirroring the documented
// contract).
func (s AppliesSpec) Matches(stack *Stack) bool {
	if stack == nil || s.IsEmpty() {
		return true
	}
	pass := func(have string, allow []string) bool {
		if len(allow) == 0 || have == "" {
			return true
		}
		for _, a := range allow {
			if strings.EqualFold(a, have) {
				return true
			}
		}
		return false
	}
	return pass(stack.Server, s.Server) &&
		pass(stack.Language, s.Language) &&
		pass(stack.Framework, s.Framework) &&
		pass(stack.CMS, s.CMS) &&
		pass(stack.CDN, s.CDN) &&
		pass(stack.WAF, s.WAF)
}

// PatchedIn declares which version of each stack field a check
// considers fixed. Keys are lowercased Stack field names ("server",
// "language", "framework", "cms", "cdn", "waf"); values are version
// strings parsed by Stack.CompareVersion. The .lua surface:
//
//	patched_in = { cms = "6.2", framework = "4.18.0" }
//
// Semantically, "if this check fires, then the host's <field> version
// is below <value>" (because the vendor patched the issue at <value>
// and the check would not trip on a patched deployment). PatchedIn is
// metadata, not a gate: checks declared with `applies_to = { cms =
// {"wordpress"} }` still run regardless of the banner version, because
// (1) banners are unreliable and (2) a check tripping anyway is the
// most useful signal the engine has about the actual deployed version.
//
// PatchedIn is read by the engine at finding-emit time; see the
// version-inference path in lua_engine.LuaCheck.Run.
type PatchedIn map[string]string

// VersionInference is a single derived observation produced by
// cross-referencing a PatchedIn declaration against the live Stack.
// The kind discriminates the rendering / severity the engine attaches
// when materializing the observation as a Finding.
//
// Kind values:
//
//   - "inferred": the stack carries no version for the field, but the
//     check fired - therefore the deployed version is below
//     PatchedVersion. Surfaced as an info-level "version inferred"
//     observation alongside the vuln finding.
//   - "patched_but_fired": the stack reports a version >= the patched
//     threshold yet the check still fired. Surfaced as a separate
//     observation suggesting a regression, partial patch, or version
//     banner spoofing. Severity inherits from the source finding.
//
// When the stack reports a version < PatchedVersion (the expected
// case for a working detection) no observation is emitted: the
// finding's existing severity / detail already convey the picture.
type VersionInference struct {
	Kind           string // "inferred" or "patched_but_fired"
	Field          string // lowercased stack field name
	DetectedName   string // the stack's value for Field (e.g. "wordpress")
	PatchedVersion string // the threshold declared in PatchedIn
	BannerVersion  string // the version the stack reports (empty for "inferred")
}

// Infer cross-references p against stack and returns one observation
// per (field, version) pair that warrants a derived finding. Callers
// pass these to a renderer that builds the actual Finding (the
// renderer owns the user-visible strings; this package owns the
// algorithm).
//
// A nil stack returns nil observations - no fingerprint means no
// signal to cross-reference, and the source finding is left alone.
// A nil / empty PatchedIn map also returns nil.
func (p PatchedIn) Infer(stack *Stack) []VersionInference {
	if stack == nil || len(p) == 0 {
		return nil
	}
	var out []VersionInference
	for rawField, patchedVersion := range p {
		field := strings.ToLower(rawField)
		detected := stackFieldValue(stack, field)
		if detected == "" {
			// No detection for this field - we cannot tie the
			// inference to a vendor name, so skip rather than emit
			// a "version inferred for cms=" with an empty subject.
			continue
		}
		banner := stack.Versions[field]
		if banner == "" {
			out = append(out, VersionInference{
				Kind:           "inferred",
				Field:          field,
				DetectedName:   detected,
				PatchedVersion: patchedVersion,
			})
			continue
		}
		cmp, ok := stack.CompareVersion(field, patchedVersion)
		if !ok {
			// Parse failure on either side - skip rather than emit
			// noise. The reporter would otherwise have to render
			// "could not compare X to Y" which carries no signal.
			continue
		}
		if cmp >= 0 {
			out = append(out, VersionInference{
				Kind:           "patched_but_fired",
				Field:          field,
				DetectedName:   detected,
				PatchedVersion: patchedVersion,
				BannerVersion:  banner,
			})
		}
	}
	return out
}

// stackFieldValue returns the lowercased value stored in stack.<field>,
// or "" when the field name is not one of the documented six. Pulled
// out so both AppliesSpec.Matches and PatchedIn.Infer share one
// switch.
func stackFieldValue(stack *Stack, field string) string {
	switch strings.ToLower(field) {
	case "server":
		return stack.Server
	case "language":
		return stack.Language
	case "framework":
		return stack.Framework
	case "cms":
		return stack.CMS
	case "cdn":
		return stack.CDN
	case "waf":
		return stack.WAF
	}
	return ""
}
