package lua_engine

import "github.com/londonmax12/hyperz/internal/fingerprint"

// This file exposes the content-discovery check's helpers to the Lua
// bridge. Sibling to content_discovery.go (and content_discovery_paths.go):
// forwards into the package-private catalogue resolver, soft-404
// detectors, and probe-count constants so the Lua port runs the same
// sweep the Go check does.

// ContentDiscoveryEntryLua is one wordlist entry surfaced to the Lua
// content-discovery port. Mirrors discoveryEntry verbatim - the .lua
// port reads these fields and composes finding text from them.
type ContentDiscoveryEntryLua struct {
	Path                 string
	Severity             string
	Title                string
	Detail               string
	CWE                  string
	OWASP                string
	Remediation          string
	Marker               string
	ExpectedContentTypes []string
	Emit                 bool
}

// ContentDiscoveryEntriesLua returns the wordlist entries the main
// sweep should probe against hostname, filtered by aggressive level
// and stack constraint. Host-named backup synthetics (when the
// catalogue defines a generator) are appended in the order the Go
// check produces. Returning a flat slice keeps the .lua iteration
// shape simple.
//
// catalogue selects which registered wordlist to walk; pass "common"
// for the canonical content-discovery list, or any name a future
// sibling catalogue is registered under. Unknown / empty names fall
// back to "common" so a Lua-side typo doesn't silently turn into a
// no-op sweep.
func ContentDiscoveryEntriesLua(catalogue string, aggressive bool, hostname string, stack *fingerprint.Stack) []ContentDiscoveryEntryLua {
	cat := resolveDiscoveryCatalogue(catalogue)
	out := make([]ContentDiscoveryEntryLua, 0, len(cat.entries)+8)
	for _, e := range cat.entries {
		if e.Aggressive && !aggressive {
			continue
		}
		if !e.appliesTo(stack) {
			continue
		}
		out = append(out, toContentDiscoveryEntryLua(e))
	}
	if cat.hostBackup != nil {
		for _, e := range cat.hostBackup(hostname) {
			out = append(out, toContentDiscoveryEntryLua(e))
		}
	}
	return out
}

// ContentDiscoveryFollowUpsLua returns the second-wave entries to
// probe given the set of paths whose first-wave probes fired and the
// set already probed. catalogue picks which registered follow-up
// group set to evaluate, mirroring ContentDiscoveryEntriesLua's
// resolution rule.
func ContentDiscoveryFollowUpsLua(catalogue string, hits map[string]struct{}, probed map[string]struct{}, stack *fingerprint.Stack) []ContentDiscoveryEntryLua {
	if len(hits) == 0 {
		return nil
	}
	cat := resolveDiscoveryCatalogue(catalogue)
	var out []ContentDiscoveryEntryLua
	queued := map[string]struct{}{}
	for _, g := range cat.followUps {
		triggered := false
		for _, t := range g.Triggers {
			if _, ok := hits[t]; ok {
				triggered = true
				break
			}
		}
		if !triggered {
			continue
		}
		for _, e := range g.Entries {
			if _, dup := probed[e.Path]; dup {
				continue
			}
			if _, dup := queued[e.Path]; dup {
				continue
			}
			if !e.appliesTo(stack) {
				continue
			}
			queued[e.Path] = struct{}{}
			out = append(out, toContentDiscoveryEntryLua(e))
		}
	}
	return out
}

func toContentDiscoveryEntryLua(e discoveryEntry) ContentDiscoveryEntryLua {
	cts := make([]string, len(e.ExpectedContentTypes))
	copy(cts, e.ExpectedContentTypes)
	return ContentDiscoveryEntryLua{
		Path:                 e.Path,
		Severity:             string(e.Severity),
		Title:                e.Title,
		Detail:               e.Detail,
		CWE:                  e.CWE,
		OWASP:                e.OWASP,
		Remediation:          e.Remediation,
		Marker:               e.Marker,
		ExpectedContentTypes: cts,
		Emit:                 e.Emit,
	}
}

// ContentDiscoveryBodyHashPrefixLua wraps bodyHashPrefix so the .lua
// port uses the exact same SHA1[:8] prefix the Go check uses for
// soft-404 fingerprinting.
func ContentDiscoveryBodyHashPrefixLua(body []byte) string {
	return bodyHashPrefix(body)
}

// ContentDiscoveryContentTypeFamilyLua exposes contentTypeFamily so
// the soft-404 baseline match runs on the same stripped family form
// on both sides.
func ContentDiscoveryContentTypeFamilyLua(ct string) string {
	return contentTypeFamily(ct)
}

// ContentDiscoveryContentTypeFamilyAllowedLua exposes
// contentTypeFamilyAllowed so the markerless-entry filter behaves
// identically.
func ContentDiscoveryContentTypeFamilyAllowedLua(ct string, allowed []string) bool {
	return contentTypeFamilyAllowed(ct, allowed)
}

// ContentDiscoveryLengthCloseToLua wraps lengthCloseTo so the soft-404
// length-proximity rule is single-sourced.
func ContentDiscoveryLengthCloseToLua(a, b int) bool {
	return lengthCloseTo(a, b)
}

// ContentDiscoveryCanaryPathLua mints a fresh canary suffix the .lua
// baseline probes. Two random twin halves + ".bad" matches the Go
// check's NewCanary()-NewCanary().bad shape so any host-side
// dictionary lookup behaves the same way.
func ContentDiscoveryCanaryPathLua() string {
	return "/" + NewCanary() + "-" + NewCanary() + ".bad"
}

// ContentDiscoveryBaselineProbes returns the canary probe count the
// .lua baseline issues per host. Mirrors contentDiscoveryBaselineProbes.
func ContentDiscoveryBaselineProbes() int { return contentDiscoveryBaselineProbes }

// ContentDiscoveryBodyCap returns the per-probe body-read cap.
func ContentDiscoveryBodyCap() int { return contentDiscoveryBodyCap }
