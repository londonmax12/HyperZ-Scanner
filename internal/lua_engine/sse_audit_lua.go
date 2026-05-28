package lua_engine

// This file exposes the sse-audit check's helpers to the Lua bridge.
// Sibling to sse_audit.go: forwards into the package-private content-
// type gate + EventSource literal scanner so the Lua port runs the
// same sweep the Go check does.

// IsEventStreamContentType reports whether ct names a Server-Sent
// Events stream. Parameters (charset, boundary) are stripped before
// comparison so a perfectly labeled response is not skipped on a
// technicality. Mirrors isEventStream so the Lua port and the
// Go original gate on the same content-type rule.
func IsEventStreamContentType(ct string) bool { return isEventStream(ct) }

// FindEventSourceLiteralsLua scans body for `new EventSource(...)`
// constructions and returns the URL captures in document order
// (duplicates preserved; the caller dedupes after resolving against a
// base URL). Bounded scan: only the first sseBodyCap bytes are
// inspected, matching the Go check.
func FindEventSourceLiteralsLua(body []byte) []string {
	if len(body) > sseBodyCap {
		body = body[:sseBodyCap]
	}
	matches := sseEventSourceRE.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 2 {
			out = append(out, string(m[1]))
		}
	}
	return out
}
