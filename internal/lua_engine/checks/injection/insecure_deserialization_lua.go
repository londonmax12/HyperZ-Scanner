package injection

// This file exposes the insecure-deserialization check's helpers to
// the Lua bridge. Sibling to insecure_deserialization.go: forwards
// into the package-private catalogue resolver + per-format matchers
// so the Lua port consumes the same format set the Go check does.

// DeserialFormatLua names one server-side deserialization format the
// insecure-deserialization Lua port surfaces. Same shape across the
// passive (fingerprint) and active (probe) arms so the .lua file can
// iterate one catalogue and route by Name when it builds findings.
type DeserialFormatLua struct {
	Name         string
	Label        string
	ProbePayload string
	ErrorPats    []string
}

// DeserialFormatListLua returns the named catalogue's format list
// translated into the Lua-bridge shape. "http_body" covers the seven
// HTTP-body deserialization formats this package has always shipped
// (Java, .NET, pickle, Ruby Marshal, PHP, node-serialize, YAML);
// unknown / empty catalogue names fall back to "http_body" via
// resolveDeserialCatalogue. The .lua port reads the list once per
// Run and uses Name to route between the per-format probe / match
// helpers.
func DeserialFormatListLua(catalogue string) []DeserialFormatLua {
	cat := resolveDeserialCatalogue(catalogue)
	out := make([]DeserialFormatLua, 0, len(cat.formats))
	for _, f := range cat.formats {
		pats := make([]string, len(f.errorPats))
		copy(pats, f.errorPats)
		out = append(out, DeserialFormatLua{
			Name:         f.name,
			Label:        f.label,
			ProbePayload: f.probePayload,
			ErrorPats:    pats,
		})
	}
	return out
}

// DeserialClassifyValueLua returns the (name, label) of the first
// format in the named catalogue whose fingerprint matches s, or
// ("", "") when no format matched. Wraps the Go check's
// classifyDeserial so the passive arm of the .lua port runs the same
// detection over cookie / query / form-input values.
func DeserialClassifyValueLua(catalogue, s string) (string, string) {
	fp := classifyDeserial(s, resolveDeserialCatalogue(catalogue))
	if fp == nil {
		return "", ""
	}
	return fp.name, fp.label
}

// DeserialMatchAllLua returns the union of error patterns across
// every format in the named catalogue that appear in body. The .lua
// port uses this to build the baseline pattern set so per-format
// probes can subtract what was already present.
func DeserialMatchAllLua(catalogue string, body []byte) []string {
	return matchDeserialAll(body, resolveDeserialCatalogue(catalogue))
}

// DeserialMatchFormatLua returns the subset of formatName's error
// patterns present in body. catalogue selects the format set
// formatName is looked up in (e.g. "http_body"); formatName is the
// name slug exposed by DeserialFormatListLua (e.g. "java", "dotnet").
func DeserialMatchFormatLua(catalogue string, body []byte, formatName string) []string {
	cat := resolveDeserialCatalogue(catalogue)
	for _, f := range cat.formats {
		if f.name == formatName {
			return matchDeserialFormat(body, f)
		}
	}
	return nil
}

// DeserialBodyMarkerLua returns the human-readable label of the first
// deserialization fingerprint visible in body, or "" when none.
// Catalogue-independent: the marker set is a fixed list of base64 /
// text prefixes hardcoded in bodyDeserialMarker rather than read from
// the format catalogue.
func DeserialBodyMarkerLua(body []byte) string {
	return bodyDeserialMarker(body)
}
