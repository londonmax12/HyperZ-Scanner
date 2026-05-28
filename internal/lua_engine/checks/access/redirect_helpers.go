package access

// This file exposes the open-redirect detection helpers as exported
// package-level functions so callers outside `checks` (notably the
// Lua bridge) can reach the same browser-quirk normalization and
// body-sink scanning the Go check uses. Keeping a thin wrapper layer
// instead of renaming the existing unexported names preserves the
// open_redirect.go author's intent (these are internal building
// blocks) while making the same logic available through the bridge
// without a parallel re-implementation drifting from the original.
//
// Every function here is a 1:1 forwarder. Logic lives in
// open_redirect.go alongside its tests; adding bridge-callable
// surface here means a single canonical implementation governs both
// Go-authored and Lua-authored checks.

// IsRedirectStatus reports whether code is a redirect status that
// carries a Location header. Forwards to isRedirectStatus; see the
// internal helper for the accepted code list.
func IsRedirectStatus(code int) bool { return isRedirectStatus(code) }

// LocationTargetsHost reports whether s, resolved the way a real
// browser would, navigates to wantHost. Used by Lua checks to
// reproduce the open-redirect probe's host comparison (which
// includes a backslash / multi-slash normalization pass) without
// reimplementing the parser in Lua.
func LocationTargetsHost(s, wantHost string) bool { return locationTargetsHost(s, wantHost) }

// FindBodyRedirectSink scans body for a JavaScript navigation API or
// meta-refresh tag whose target points at canaryHost. Returns the
// matched target string and a human-readable kind label, or
// ("", "") when nothing matches. The regex engine stays in Go;
// Lua-side authors only see the call.
func FindBodyRedirectSink(body []byte, canaryHost string) (target, kind string) {
	return findBodyRedirectSink(body, canaryHost)
}

// LooksRedirectish reports whether path contains one of the
// keywords ("login", "logout", "auth", "sso", "redirect") that flag
// a URL as "probably handles a redirect", earning it the full
// canonical sweep at LevelDefault. Exposed so a Lua port of
// open-redirect can apply the same gating without re-listing the
// keywords on the Lua side (which would risk drift over time).
func LooksRedirectish(path string) bool { return looksRedirectish(path) }
