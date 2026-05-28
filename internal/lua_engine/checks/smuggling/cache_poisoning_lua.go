package smuggling

import (
	"net/http"
	"net/url"
	"strings"
)

// This file exposes the cache-poisoning check's helpers to the Lua
// bridge. Sibling to cache_poisoning.go: forwards into the package-
// private probe table, cache-hint detector, reflection scanner, and
// deception suffix builder so the Lua port runs the same sweep the Go
// check does.

// CachePoisonHeaderProbeLua is one unkeyed-header probe the cache-
// poisoning Lua port sends. Header / Value are the wire pair; Canary
// is what the reflection check searches for in the response; Kind
// flags whether the probe should also consult responseDiverged
// (path-rewrite primitives) on top of the reflection check.
// DeceptionMessage is the human-facing detail lead-in.
type CachePoisonHeaderProbeLua struct {
	Header           string
	Value            string
	Canary           string
	Kind             string
	DeceptionMessage string
}

// CachePoisonHeaderProbesLua exposes the curated probe list. Mirrors
// the Go check's cachePoisonHeaderProbes() one-for-one so the Lua port
// runs the same probes in the same order.
func CachePoisonHeaderProbesLua() []CachePoisonHeaderProbeLua {
	return []CachePoisonHeaderProbeLua{
		{
			Header:           "X-Forwarded-Host",
			Value:            cachePoisonCanaryHost,
			Canary:           cachePoisonCanaryHost,
			Kind:             "reflection",
			DeceptionMessage: "Back-end echoes X-Forwarded-Host into the response body or absolute URLs without keying the cache on it.",
		},
		{
			Header:           "X-Forwarded-Scheme",
			Value:            "nothttps",
			Canary:           "nothttps://",
			Kind:             "reflection",
			DeceptionMessage: "Back-end rewrites generated absolute URLs to use the attacker-supplied scheme (X-Forwarded-Scheme).",
		},
		{
			Header:           "X-Forwarded-Proto",
			Value:            "nothttps",
			Canary:           "nothttps://",
			Kind:             "reflection",
			DeceptionMessage: "Back-end rewrites generated absolute URLs to use the attacker-supplied scheme (X-Forwarded-Proto).",
		},
		{
			Header:           "X-Original-URL",
			Value:            cachePoisonCanaryPath,
			Canary:           cachePoisonCanaryPath,
			Kind:             "reflection-or-diverged",
			DeceptionMessage: "Back-end honours X-Original-URL to override the routed path without rechecking authorization.",
		},
		{
			Header:           "X-Rewrite-URL",
			Value:            cachePoisonCanaryPath,
			Canary:           cachePoisonCanaryPath,
			Kind:             "reflection-or-diverged",
			DeceptionMessage: "Back-end honours X-Rewrite-URL to override the routed path without rechecking authorization.",
		},
	}
}

// CachePoisonHasCacheHint forwards hasCacheHint so the Lua port short-
// circuits the unkeyed-header arm on pages whose baseline response
// carries no cache hint (Cache-Control, Age, X-Cache, CF-Cache-Status,
// Via). Without a shared cache in the path the worst case is local
// reflection; gating prevents the noisy probe from firing on a target
// the bug class does not apply to.
func CachePoisonHasCacheHint(h http.Header) bool { return cacheHintsPresent(h) }

// CachePoisonFindReflection wraps findReflection so the Lua port can
// run the same body + header lookup the Go check uses. needle is the
// canary string; resp + body are the probe response; baseBody is the
// baseline body bytes (used to drop pre-existing echoes). Returns the
// location string ("response body", "Location header", "") and a bool.
func CachePoisonFindReflection(needle string, headers http.Header, body, baseBody []byte) (string, bool) {
	lowerNeedle := strings.ToLower(needle)
	if needle == "" {
		return "", false
	}
	if len(baseBody) > 0 && strings.Contains(strings.ToLower(string(baseBody)), lowerNeedle) {
		return "", false
	}
	if len(body) > 0 && strings.Contains(strings.ToLower(string(body)), lowerNeedle) {
		return "response body", true
	}
	for _, h := range []string{"Location", "Link", "Set-Cookie", "Content-Location", "Refresh"} {
		for _, v := range headers.Values(h) {
			if strings.Contains(strings.ToLower(v), lowerNeedle) {
				return h + " header", true
			}
		}
	}
	return "", false
}

// CachePoisonResponseDiverged wraps responseDiverged. status / body are
// the probe response shape; baseStatus / baseBody are the baseline. Used
// by the path-rewrite probes (X-Original-URL / X-Rewrite-URL) where the
// canary path itself rarely echoes back; instead the signal is "the
// response looks like a different page".
func CachePoisonResponseDiverged(status int, body []byte, baseStatus int, baseBody []byte) bool {
	if status != baseStatus {
		return true
	}
	if len(body) == 0 || len(baseBody) == 0 {
		return false
	}
	a, b := len(body), len(baseBody)
	if a < b {
		a, b = b, a
	}
	if a-b > a/4 {
		return true
	}
	return false
}

// CachePoisonBodiesMatch wraps bodiesMatch for the cache-deception arm.
// The two snapshots are the deception-probe body vs. the baseline body;
// returns true when they look like the same authenticated page modulo
// rotating tokens.
func CachePoisonBodiesMatch(deceived, baseline []byte) bool {
	return bodiesMatch(deceived, baseline)
}

// CachePoisonCacheControlForbidsStorage forwards the Cache-Control
// "no-store" / "private" detector. The deception arm uses this to
// downgrade severity from High to Medium when the upstream explicitly
// forbids storage.
func CachePoisonCacheControlForbidsStorage(cc string) bool { return cacheControlForbidsStorage(cc) }

// CachePoisonIsAuthLikelyPath forwards the per-path heuristic the cache-
// deception arm uses to gate the probe at LevelDefault.
func CachePoisonIsAuthLikelyPath(path string) bool { return isAuthLikelyPath(path) }

// CachePoisonDeceptionURL forwards deceptionURL. raw is the absolute
// target URL; the result is target with cacheDeceptionSuffix appended
// to its path (or "" when the target already ends with the suffix).
func CachePoisonDeceptionURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return deceptionURL(u)
}

// CachePoisonParseVary returns the lowercased Vary header set. The
// Lua port uses this to check whether a header is keyed before
// emitting an unkeyed-header finding.
func CachePoisonParseVary(v string) []string {
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

// CachePoisonDeceptionSuffix exposes the static-asset suffix the cache-
// deception arm appends to a probe URL. Centralised so the Go and Lua
// checks agree on the wire shape; a change to "what does a cache-
// rule trigger on" lands once.
func CachePoisonDeceptionSuffix() string { return cacheDeceptionSuffix }

// CachePoisonProbeURL forwards cachePoisonProbeURL so the Lua port
// builds unkeyed-header probe URLs through the same random-
// cachebuster pipeline the Go check uses. Both implementations MUST
// route every probe through this helper; firing at the canonical
// (method, path, query) instead would mean the probe response a
// vulnerable cache stores lands on the exact key real victims hit.
func CachePoisonProbeURL(target string) (string, error) { return cachePoisonProbeURL(target) }

// CachePoisonCachebusterParam exposes the cachebuster query name so a
// parity test can assert both implementations append it and never hit
// the canonical URL bare.
func CachePoisonCachebusterParam() string { return cachePoisonCachebusterParam }

// CachePoisonCanaryHost / CachePoisonCanaryPath expose the canary
// values the Lua port stamps onto evidence + dedupe keys. Mirrors
// the Go check constants 1:1.
func CachePoisonCanaryHost() string { return cachePoisonCanaryHost }
func CachePoisonCanaryPath() string { return cachePoisonCanaryPath }
