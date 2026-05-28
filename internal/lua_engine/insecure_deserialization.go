package lua_engine

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

// deserialFormat fingerprints one server-side serialization format. The
// same struct fuels both arms: detectRaw / detectText drive the
// fingerprint scan, errorPats and probePayload drive the active probe.
type deserialFormat struct {
	name  string
	label string
	// detectRaw runs against the base64-decoded byte view of a candidate
	// value. Use for binary formats (Java, .NET, pickle, Ruby).
	detectRaw func(b []byte) bool
	// detectText runs against the URL-decoded string view of a candidate
	// value. Use for text formats (PHP, node-serialize, YAML).
	detectText func(s string) bool
	// errorPats are lowercase substrings the format's deserializer leaves
	// in the response when it fails to parse a malformed input. Matched
	// case-insensitively after the body is lower-cased once.
	errorPats []string
	// probePayload is the malformed-but-format-valid blob the active arm
	// sends through each Sink. Designed to break the parser, not run any
	// constructor.
	probePayload string
}

// phpSerializeRe is the leading-token signature for a PHP serialize()
// output. Anchored to the start of the (trimmed) string so we don't match
// stray "O:" inside JSON or prose.
var phpSerializeRe = regexp.MustCompile(`^(?:O:\d+:"[^"]+":\d+:\{|a:\d+:\{|s:\d+:")`)

// deserialFormatList is the curated format list backing the canonical
// "http_body" catalogue. Package-scope so it is constructed once at init
// rather than allocated on every classifyDeserial / probeSink /
// matchDeserialAll call (those run in the hot per-page loop). Callers
// must treat it as read-only - no slot is filtered or reordered
// today, and adding a per-call mutation would race across goroutines.
var deserialFormatList = []deserialFormat{
	{
		name:  "java",
		label: "Java ObjectInputStream",
		detectRaw: func(b []byte) bool {
			return len(b) >= 4 && b[0] == 0xac && b[1] == 0xed && b[2] == 0x00 && b[3] == 0x05
		},
		errorPats: []string{
			"java.io.streamcorruptedexception",
			"java.io.optionaldataexception",
			"java.io.invalidclassexception",
			"java.io.eofexception",
			"java.io.objectinputstream",
			"java.io.notserializableexception",
			"java.lang.classnotfoundexception",
			"readobject",
			"writeobject",
			"serialversionuid",
		},
		// \xac\xed\x00\x05 TC_HEADER + 0x73 TC_OBJECT + 0x72 TC_CLASSDESC
		// + 0x00 0x00 (class name length 0) then EOF. The reader will
		// throw StreamCorruptedException as soon as it tries to consume
		// the class-name string.
		probePayload: "rO0ABXNyAAA",
	},
	{
		name:  "dotnet",
		label: ".NET BinaryFormatter / LosFormatter",
		detectRaw: func(b []byte) bool {
			return bytes.HasPrefix(b, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff})
		},
		errorPats: []string{
			"system.runtime.serialization.serializationexception",
			"system.runtime.serialization",
			"binaryformatter",
			"losformatter",
			"netdatacontractserializer",
			"the input stream is not a valid binary format",
			"end of stream encountered",
			"cannot deserialize",
			"objectmanager.dofixups",
		},
		// SerializationHeaderRecord (record id 0) with rootId=1,
		// headerId=-1, major=1, minor=0 then a truncated next record so
		// the stream walker hits End of Stream.
		probePayload: "AAEAAAD/////AQAAAAAAAAAA",
	},
	{
		name:  "pickle",
		label: "Python pickle",
		detectRaw: func(b []byte) bool {
			if len(b) < 2 {
				return false
			}
			if b[0] != 0x80 {
				return false
			}
			switch b[1] {
			case 0x02, 0x03:
				return true
			case 0x04, 0x05:
				return len(b) >= 3 && b[2] == 0x95
			}
			return false
		},
		errorPats: []string{
			"_pickle.unpicklingerror",
			"pickle.unpicklingerror",
			"cpickle.unpicklingerror",
			"unpickling stack underflow",
			"pickle data was truncated",
			"unsupported pickle protocol",
			"stack_global requires str",
			"unpickler",
			"could not find mark",
		},
		// PROTO 4, FRAME opcode with declared length 0x0a but no
		// payload that follows. _pickle raises "pickle data was
		// truncated" before reaching any constructor.
		probePayload: "gASVCgAAAAAAAAAA",
	},
	{
		name:  "ruby",
		label: "Ruby Marshal",
		detectRaw: func(b []byte) bool {
			if len(b) < 3 || b[0] != 0x04 || b[1] != 0x08 {
				return false
			}
			// Marshal type tags. Restrict to the documented set so we
			// don't match arbitrary two-byte prefixes that happen to be
			// 04 08.
			switch b[2] {
			case 'T', 'F', '0', 'I', 'o', 'u', 'U', '[', '{', ':', ';', '@', 'i', 'l', '"', 'f', 'c', 'm', 'e':
				return true
			}
			return false
		},
		errorPats: []string{
			"incompatible marshal file format",
			"marshal data too short",
			"typeerror: incompatible marshal",
			"argumenterror: marshal",
			"dump format error",
			"marshal.load",
			"undefined class/module",
		},
		// \x04\x08 version + 'o' (TC_OBJECT) + ':' (symbol prefix) then
		// EOF. Marshal.load throws ArgumentError "marshal data too
		// short" before reading the class name.
		probePayload: "BAhvOg==",
	},
	{
		name:  "php",
		label: "PHP unserialize()",
		detectText: func(s string) bool {
			return phpSerializeRe.MatchString(strings.TrimSpace(s))
		},
		errorPats: []string{
			"unserialize(",
			"__php_incomplete_class",
			"notice: unserialize",
			"warning: unserialize",
			"php notice:  unserialize",
			"php warning:  unserialize",
			"unable to find class",
			"session_decode",
		},
		// Object of a nonexistent class with declared field count 0.
		// PHP will emit a Notice / Warning ("unserialize(): Unable to
		// find class") at session_decode / unserialize time without
		// ever invoking a constructor.
		probePayload: `O:30:"HyperzNoSuchClassProbeXyz123":0:{}`,
	},
	{
		name:  "node-serialize",
		label: "Node node-serialize",
		detectText: func(s string) bool {
			return strings.Contains(s, "_$$ND_FUNC$$_")
		},
		errorPats: []string{
			"node-serialize",
			"_$$nd_func$$_",
			"unserialize is not a function",
		},
		// A JSON envelope carrying the node-serialize marker but
		// truncated mid-function so eval() throws SyntaxError before
		// invoking any code.
		probePayload: `{"hpzc":"_$$ND_FUNC$$_truncated`,
	},
	{
		name:  "yaml",
		label: "YAML unsafe load",
		detectText: func(s string) bool {
			return strings.Contains(s, "!!python/object") ||
				strings.Contains(s, "!!ruby/object") ||
				strings.Contains(s, "!!perl/")
		},
		errorPats: []string{
			"yaml.constructor.constructorerror",
			"yaml::syntax",
			"psych::disallowedclass",
			"yaml::typeerror",
			"could not determine a constructor for the tag",
			"could not load module",
			"cannot find module",
		},
		// !!python/object tag pointing at a module/function that does
		// not exist. PyYAML raises ConstructorError on the missing
		// import before any callable is invoked.
		probePayload: `!!python/object/apply:hpzc_no_such_module.no_such_func ["hpzc"]`,
	},
}

// deserialCatalogue groups a named subset of deserialization formats
// the bridge surfaces to .lua check authors. The Lua bridge takes
// the name as ctx.deserial.{formats,classify,match_all,match_format}
// first argument and resolves it through resolveDeserialCatalogue.
// A future check that wants to extend the catalogue with a vendor-
// specific format (e.g. msgpack, protobuf RPC envelopes) registers
// its own catalogue here rather than mutating the canonical list -
// per-check format isolation prevents one check's new entries from
// leaking into another check's classify / match sweep.
type deserialCatalogue struct {
	formats []deserialFormat
}

// deserialCatalogues is the named-catalogue registry. "http_body"
// covers the seven HTTP-body deserialization formats this package
// has always shipped (Java, .NET, pickle, Ruby Marshal, PHP, node-
// serialize, YAML); sibling catalogues (e.g. "rpc_envelopes" for
// RMI / protobuf-RPC) add themselves to this map and the Lua bridge
// surfaces them automatically.
var deserialCatalogues = map[string]deserialCatalogue{
	"http_body": {formats: deserialFormatList},
}

// resolveDeserialCatalogue returns the named catalogue, falling back
// to "http_body" when name is empty or unknown. Same typo-tolerance
// rule the other bridge catalogue resolvers use.
func resolveDeserialCatalogue(name string) deserialCatalogue {
	if cat, ok := deserialCatalogues[name]; ok {
		return cat
	}
	return deserialCatalogues["http_body"]
}

// classifyDeserial reports the first deserialization format in cat
// whose fingerprint matches s, or nil if none does. s is interpreted
// under three views: the raw string, the URL-decoded string, and the
// base64-decoded bytes (tried under standard, raw-standard, URL-safe,
// and raw-URL-safe alphabets). Binary formats compare on the
// base64-decoded view; text formats compare on the URL-decoded string.
//
// A minimum decoded length of 4 bytes keeps random short b64-decodable
// strings from triggering false matches against the longer raw headers.
func classifyDeserial(s string, cat deserialCatalogue) *deserialFormat {
	if s == "" {
		return nil
	}
	text := strings.TrimSpace(s)
	text = strings.Trim(text, `"'`)
	if u, err := url.QueryUnescape(text); err == nil {
		text = u
	}
	var raw []byte
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(text); err == nil && len(b) >= 4 {
			raw = b
			break
		}
	}
	for i := range cat.formats {
		format := &cat.formats[i]
		if format.detectText != nil && format.detectText(text) {
			return format
		}
		if format.detectRaw != nil && raw != nil && format.detectRaw(raw) {
			return format
		}
	}
	return nil
}

// matchDeserialAll returns every error pattern across every known format
// that appears in body. Used to build the baseline pattern set so the
// per-format probe can compare what the payload added versus what was
// already there. cat is the format set to walk; "http_body" covers
// the canonical seven this package ships with.
func matchDeserialAll(body []byte, cat deserialCatalogue) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, format := range cat.formats {
		for _, pattern := range format.errorPats {
			if bytes.Contains(lower, []byte(pattern)) {
				hits = append(hits, pattern)
			}
		}
	}
	return hits
}

// matchDeserialFormat returns the subset of format.errorPats found in body.
// Body is lower-cased once per call; patterns are already lower-cased so
// the scan is case-insensitive without per-pattern allocations.
func matchDeserialFormat(body []byte, format deserialFormat) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pattern := range format.errorPats {
		if bytes.Contains(lower, []byte(pattern)) {
			hits = append(hits, pattern)
		}
	}
	return hits
}

// bodyDeserialMarker reports the human-readable label of the first
// deserialization fingerprint visible in body, or "" if none. Only
// scans for distinctive text markers - the base64 prefix of a binary
// format and the text-form magic of PHP / node-serialize / YAML - since
// raw binary prefixes inside an HTML response body are too rare to be
// worth a byte scan.
func bodyDeserialMarker(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	// Case-insensitive scan for binary base64 prefixes; case-sensitive
	// search for text-form magic that would not legitimately appear in
	// rendered HTML.
	lower := bytes.ToLower(body)
	if bytes.Contains(lower, []byte("ro0ab")) {
		return "Java ObjectInputStream (base64 rO0AB...)"
	}
	if bytes.Contains(body, []byte("AAEAAAD/////")) {
		return ".NET BinaryFormatter (base64 AAEAAAD/////...)"
	}
	if bytes.Contains(body, []byte("_$$ND_FUNC$$_")) {
		return "node-serialize (_$$ND_FUNC$$_ marker)"
	}
	if bytes.Contains(body, []byte("!!python/object")) {
		return "YAML !!python/object directive"
	}
	if bytes.Contains(body, []byte("!!ruby/object")) {
		return "YAML !!ruby/object directive"
	}
	return ""
}

