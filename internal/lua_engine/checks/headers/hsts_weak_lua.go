package headers

// This file exposes the hsts-weak check's helpers to the Lua bridge.
// Sibling to hsts_weak.go: forwards into the package-private
// parseHSTS / hstsParseError types so the Lua port consumes the exact
// same directive-split + duplicate-detect logic the Go check runs.

// HSTSDirectives is the parsed form of one Strict-Transport-Security
// header value: lower-cased directive name -> value (empty for flag-
// only directives) plus the structural parse errors the spec considers
// fatal (duplicate directive names).
type HSTSDirectives struct {
	Directives map[string]string
	Errors     []HSTSParseError
}

// HSTSParseError mirrors hstsParseError. Exported so the Lua port can
// iterate over the same parser output the Go check does.
type HSTSParseError struct {
	ID     string
	Detail string
}

// ParseHSTSHeader wraps the package-private parseHSTS so the Lua hsts-
// weak port consumes the exact same directive-split + duplicate-detect
// logic the Go check runs.
func ParseHSTSHeader(value string) HSTSDirectives {
	d, errs := parseHSTS(value)
	out := HSTSDirectives{Directives: d}
	for _, e := range errs {
		out.Errors = append(out.Errors, HSTSParseError{ID: e.id, Detail: e.detail})
	}
	return out
}
