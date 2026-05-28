package lua_engine

import (
	"context"

	"github.com/londonmax12/hyperz/internal/page"
)

// This file exposes the ws-audit check's helpers to the Lua bridge.
// Sibling to ws_audit.go: forwards into the package-private endpoint
// discovery + handshake helpers so the Lua port runs the same probes
// the Go check does.

// WSAuditDiscoverEndpointsLua wraps discoverWSEndpoints so the ws-audit
// Lua port pulls ws:// / wss:// URL literals out of a body using the
// exact same regex + dedupe + sort the Go check does. Returns the
// sorted, deduped slice of absolute endpoint URLs.
func WSAuditDiscoverEndpointsLua(body []byte) []string {
	return discoverWSEndpoints(page.Page{Body: body})
}

// WSAuditHandshakeResultLua is the per-handshake outcome the ws bridge
// hands back to the .lua port. Mirrors wsHandshake's four-return shape
// in a single struct so the bridge surface is one helper, not four
// loose values to thread through Lua.
type WSAuditHandshakeResultLua struct {
	Accepted bool
	Snippet  string
	Status   int
}

// WSAuditHandshakeLua wraps wsHandshake. Returns Accepted=true only
// when the server returned 101 Switching Protocols and the
// Sec-WebSocket-Accept derived correctly from the bridge's
// per-handshake key - the same two-gate rule the Go check uses to
// distinguish a real WS server from a coincidentally-101 proxy.
//
// origin is the Origin header the handshake carries. Pass
// WSAuditForeignOriginLua() to mirror the Go CSWSH probe; an empty
// string drops the Origin header entirely.
func WSAuditHandshakeLua(ctx context.Context, target, origin string) (*WSAuditHandshakeResultLua, error) {
	accepted, snippet, status, err := wsHandshake(ctx, target, origin)
	if err != nil {
		return nil, err
	}
	return &WSAuditHandshakeResultLua{
		Accepted: accepted,
		Snippet:  snippet,
		Status:   status,
	}, nil
}

// WSAuditForeignOriginLua exposes wsOrigin so the .lua port stamps
// the same foreign-Origin string into detail / wire as the Go check.
// Constant - the value is well-known (example-domain hostname) so
// findings on this never collide with a real allowlist.
func WSAuditForeignOriginLua() string { return wsOrigin }

// WSAuditMaxEndpointsPerPageLua exposes wsMaxEndpointsPerPage so the
// .lua port caps the per-page probe fan-out at the same number the Go
// check does. A test that tightens the cap (mass-endpoint stress) only
// needs to change the Go constant.
func WSAuditMaxEndpointsPerPageLua() int { return wsMaxEndpointsPerPage }
