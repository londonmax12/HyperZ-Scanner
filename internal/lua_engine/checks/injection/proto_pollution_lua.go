package injection

import "net/http"

// This file exposes the proto-pollution check's helpers to the Lua
// bridge. Sibling to proto_pollution.go: forwards into the package-
// private JSON-response sniffer + indent-width detector so the Lua
// port reads the same signals the Go check does.

// ProtoPollutionIsJSONResponse wraps isJSONResponse so the Lua port
// applies the same content-type + body-start sniffing the Go check
// uses to decide whether the json-spaces gadget applies.
func ProtoPollutionIsJSONResponse(ct string, body []byte) bool {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return isJSONResponse(h, body)
}

// ProtoPollutionJSONIndentWidth wraps jsonIndentWidth so the Lua port
// reads the indent-GCD the same way the Go check does. Returns 0 when
// no indented JSON lines are present, 1 when mixed indents collapse,
// otherwise the GCD of every observed indent run.
func ProtoPollutionJSONIndentWidth(body []byte) int {
	return jsonIndentWidth(body)
}
