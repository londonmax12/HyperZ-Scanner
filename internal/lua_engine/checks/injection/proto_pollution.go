package injection

import (
	"bytes"
	"net/http"
	"strings"
)

// isJSONResponse reports whether the observer response should be
// considered for the json-spaces gadget. Content-Type wins when
// present; otherwise a body that starts with `{` or `[` after
// whitespace stripping is treated as JSON (some APIs return correct
// JSON without setting the header).
func isJSONResponse(h http.Header, body []byte) bool {
	if h != nil {
		ct := strings.ToLower(h.Get("Content-Type"))
		if strings.Contains(ct, "application/json") || strings.Contains(ct, "+json") {
			return true
		}
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

// jsonIndentWidth returns the GCD of indent widths observed across
// every indented line in body, or 0 when no indentation is observed.
// Detection is the simple "newline followed by N spaces followed by
// a non-space non-newline byte" pattern - JSON.stringify(value,
// null, N) always produces exactly this shape for any nested
// object or array. Tabs are not treated as indentation: the
// json-spaces gadget configures a space count, never a tab count.
//
// GCD recovers the per-call indent unit regardless of which depth
// appears first in the body. JSON.stringify(value, null, 7) on a
// nested document produces 7-space (depth 1), 14-space (depth 2),
// 21-space (depth 3), ... prefixes; GCD(7, 14, 21, ...) = 7, which
// is what the gadget installed. A first-line-wins scan also lands
// on 7 in practice (depth 1 is emitted before depth 2), but GCD is
// robust to bodies where an HTTP / template preamble pushes the
// first indented run to an inner depth. On a body that mixes two
// genuinely independent indent units (e.g. an outer document at 2
// concatenated with an inner raw-JSON blob at 7) GCD collapses to
// 1, which deliberately suppresses a verdict the scanner cannot
// safely attribute.
func jsonIndentWidth(body []byte) int {
	gcd := 0
	for i := 0; i < len(body)-1; i++ {
		if body[i] != '\n' {
			continue
		}
		count := 0
		j := i + 1
		for j < len(body) && body[j] == ' ' {
			count++
			j++
		}
		if count == 0 || j >= len(body) || body[j] == '\n' || body[j] == ' ' {
			continue
		}
		if gcd == 0 {
			gcd = count
			continue
		}
		gcd = intGCD(gcd, count)
		if gcd == 1 {
			return 1
		}
	}
	return gcd
}

func intGCD(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
