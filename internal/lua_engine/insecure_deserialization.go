package lua_engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
)

// InsecureDeserialization detects server-side object-deserialization bugs
// in two complementary arms.
//
//  1. Fingerprint arm (passive scan of the baseline response). Each
//     supported format has a distinctive on-the-wire shape that survives
//     URL-encoding and base64 transport:
//
//     Java ObjectInputStream  raw \xac\xed\x00\x05         base64 rO0AB
//     .NET BinaryFormatter    raw \x00\x01\x00\x00\x00\xff\xff\xff\xff
//     base64 AAEAAAD/////
//     PHP serialize()         text O:N:"...":N:{...}, a:N:{...}
//     Python pickle           raw \x80\x02..\x80\x05       base64 gAJ/gAM/gAS/gAU
//     Ruby Marshal            raw \x04\x08<type-tag>       base64 BAg
//     node-serialize          text _$$ND_FUNC$$_
//     YAML object directives  text !!python/object, !!ruby/object, !!perl/
//
//     A fingerprint in a Set-Cookie value, a URL query parameter, or a
//     hidden form input is HIGH: a client-round-tripped serialized blob is
//     the canonical insecure-deserialization sink. The same fingerprint in
//     the rendered response body alone is MEDIUM (leakage that may or may
//     not round-trip back to a deserializer).
//
//  2. Probe arm (active per input sink). For each sink discovered by
//     SinksFor the check sends a small set of malformed-but-format-valid
//     header blobs (truncated Java TC_HEADER, a PHP object of a
//     nonexistent class, a Python pickle proto-4 stub with a frame length
//     longer than the body, etc.) and looks for deserializer-specific
//     error signatures introduced relative to a benign canary baseline.
//     A new pattern that wasn't in the baseline confirms the sink is fed
//     to a deserializer; CWE-502 fires regardless of whether a usable
//     gadget chain exists, since the presence of the deserializer is the
//     architectural defect.
//
// Probe payloads NEVER carry a usable gadget chain. They are crafted to
// trip the deserializer's parser (header magic + truncation, nonexistent
// class names, empty frames) and never reach a constructor. We
// deliberately do not import or generate ysoserial / pickle-RCE-style
// payloads even under --pollute: a scanner that detonates code against
// an unprepared target is the wrong tradeoff. Operators who need
// gadget-chain confirmation should run a dedicated exploitation tool
// against the specific finding.
//
// This is an active (LevelDefault) check. The fingerprint arm reuses the
// crawler-fetched snapshot so it costs zero extra requests; the probe arm
// is bounded by len(SinksFor(p)) * (1 baseline + len(deserialProbes())).
type InsecureDeserialization struct{}

// insecDeserialBodyCap bounds the response body the probe arm reads.
// Deserializer error traces almost always appear within the first few KB
// of an error page; the cap also keeps the per-request memory bounded
// for sites that return very large HTML on errors.
const insecDeserialBodyCap = 32 << 10

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

// deserialFormatList is the curated format list. Package-scope so it is
// constructed once at init rather than allocated on every classifyDeserial /
// probeSink / matchDeserialAll call (those run in the hot per-page loop).
// Callers must treat it as read-only - no slot is filtered or reordered
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

// classifyDeserial reports the first deserialization format whose
// fingerprint matches s, or nil if none does. s is interpreted under
// three views: the raw string, the URL-decoded string, and the
// base64-decoded bytes (tried under standard, raw-standard, URL-safe,
// and raw-URL-safe alphabets). Binary formats compare on the
// base64-decoded view; text formats compare on the URL-decoded string.
//
// A minimum decoded length of 4 bytes keeps random short b64-decodable
// strings from triggering false matches against the longer raw headers.
func classifyDeserial(s string) *deserialFormat {
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
	for i := range deserialFormatList {
		format := &deserialFormatList[i]
		if format.detectText != nil && format.detectText(text) {
			return format
		}
		if format.detectRaw != nil && raw != nil && format.detectRaw(raw) {
			return format
		}
	}
	return nil
}

// scanFingerprints inspects the baseline response for serialized data in
// surfaces that round-trip back to a server-side deserializer:
//   - Set-Cookie values (server-issued session blobs)
//   - URL query parameters
//   - hidden / visible form input default values
//
// At LevelAggressive the response body is also scanned for the unmistakable
// text-form markers (base64 prefixes, framework-specific magic). Body hits
// fire at MEDIUM since the round-trip isn't proven; the other three arms
// fire at HIGH.
func (c InsecureDeserialization) scanFingerprints(ctx context.Context, p page.Page, u *url.URL, base snapshot, add func(*Finding)) {
	// Set-Cookie: server-set cookies that round-trip on every subsequent
	// request and are typically read by the same code path that issued them.
	resp := &http.Response{Header: base.Headers}
	for _, cookie := range resp.Cookies() {
		if fp := classifyDeserial(cookie.Value); fp != nil {
			add(c.fingerprintFinding(p.URL, "Set-Cookie "+cookie.Name, fp, cookie.Value, SeverityHigh))
		}
	}

	// URL query parameters present at crawl time.
	for k, vs := range u.Query() {
		for _, v := range vs {
			if fp := classifyDeserial(v); fp != nil {
				add(c.fingerprintFinding(p.URL, "query parameter "+k, fp, v, SeverityHigh))
			}
		}
	}

	// Form input default values. Hidden inputs that carry serialized state
	// are the textbook ViewState / __VIEWSTATE shape - the server re-reads
	// them on submit through its native deserializer.
	for _, form := range p.Forms {
		for _, in := range form.Inputs {
			if in.Value == "" {
				continue
			}
			if fp := classifyDeserial(in.Value); fp != nil {
				add(c.fingerprintFinding(p.URL, "form input "+in.Name, fp, in.Value, SeverityHigh))
			}
		}
	}

	// Response body scan at LevelAggressive only. Plain-text markers in
	// the rendered HTML are leakage rather than a proven round-trip; we
	// skip the byte scan on every passive page to avoid noise.
	if LevelFrom(ctx) >= LevelAggressive && len(base.Body) > 0 {
		if marker := bodyDeserialMarker(base.Body); marker != "" {
			add(&Finding{
				Check:    "insecure-deserialization",
				Target:   p.URL,
				URL:      p.URL,
				Severity: SeverityMedium,
				Title:    fmt.Sprintf("Serialized object exposed in response body (%s)", marker),
				Detail: fmt.Sprintf(
					"The response body contains the on-the-wire shape of %s. This is leakage rather than a "+
						"proven round-trip sink: the server is emitting a serialized blob into the rendered "+
						"output, which is harmless on its own but suggests format-native serialization is used "+
						"somewhere in the request lifecycle. Investigate whether the same blob is accepted back "+
						"from the client (cookie, hidden field, query parameter) and fed to a deserializer.",
					marker),
				CWE:   "CWE-502",
				OWASP: "A08:2021 Software and Data Integrity Failures",
				Remediation: "Audit whether a server-side deserializer reads any user-influenced value. If so, replace " +
					"format-native deserialization (Java ObjectInputStream, .NET BinaryFormatter/LosFormatter, " +
					"PHP unserialize, pickle.loads, Marshal.load, node-serialize) with a data-only format such " +
					"as JSON or Protocol Buffers and validate against a schema. When format-native deserialization " +
					"is unavoidable, sign the blob with a server-side key and verify the MAC before deserializing.",
				DedupeKey: MakeKey("insecure-deserialization", ScopePage, p.URL, "body-fingerprint:"+marker),
			})
		}
	}
}

// fingerprintFinding builds the per-surface fingerprint finding. severity
// is the caller-chosen severity (HIGH for round-trip surfaces, MEDIUM for
// body-only leakage). location is a human-readable label of where the
// fingerprint was observed, included in title and detail so reports
// distinguish hits across surfaces.
func (c InsecureDeserialization) fingerprintFinding(target, location string, fp *deserialFormat, value string, severity Severity) *Finding {
	preview := value
	if len(preview) > 80 {
		preview = preview[:80] + "..."
	}
	return &Finding{
		Check:    "insecure-deserialization",
		Target:   target,
		URL:      target,
		Severity: severity,
		Title:    fmt.Sprintf("Serialized %s data carried in %s", fp.label, location),
		Detail: fmt.Sprintf(
			"%s carries a value matching the on-the-wire shape of %s (sample: %q). When the server reads this "+
				"value back through a format-native deserializer the request is one crafted gadget chain away "+
				"from remote code execution. Insecure deserialization (CWE-502) is exploitable regardless of "+
				"whether a usable gadget is known today; the architectural defect is feeding attacker-influenced "+
				"bytes to a polymorphic deserializer.",
			location, fp.label, preview),
		CWE:   "CWE-502",
		OWASP: "A08:2021 Software and Data Integrity Failures",
		Remediation: "Stop round-tripping serialized objects through the client. Replace the carrier with an opaque " +
			"server-side session ID and keep the deserialized state in server memory or a trusted store. When " +
			"the round-trip is unavoidable, sign the blob with a server-side key (HMAC) and verify the MAC " +
			"before deserializing. Restrict the deserializer's type allowlist (Java: ObjectInputFilter; " +
			".NET: ISerializationBinder; Python: a RestrictedUnpickler).",
		Evidence: &Evidence{
			RequestURL: target,
			Snippet:    fmt.Sprintf("%s value: %s", location, preview),
		},
		DedupeKey: MakeKey("insecure-deserialization", ScopePage, target, "fingerprint", "format:"+fp.name, "location:"+location),
	}
}

// probeSink runs the baseline + per-format payload sweep for one sink.
// Returns the first finding observed; dedupe collapses any subsequent
// hits on the same (loc, param) so continuing would just burn requests.
func (c InsecureDeserialization) probeSink(ctx context.Context, client *httpclient.Client, target string, sink Sink) (*Finding, error) {
	canary := NewCanary()
	_, _, baselineBody, _, err := c.send(ctx, client, sink, canary)
	if err != nil {
		return nil, err
	}
	baselineHits := matchDeserialAll(baselineBody)

	for _, format := range deserialFormatList {
		if ctx.Err() != nil {
			break
		}
		req, resp, body, truncated, err := c.send(ctx, client, sink, format.probePayload)
		if err != nil {
			return nil, err
		}
		hits := matchDeserialFormat(body, format)
		newHits := subtractPatterns(hits, baselineHits)
		if len(newHits) == 0 {
			continue
		}
		probeURL, method := "", ""
		if req != nil {
			method = req.Method
			if req.URL != nil {
				probeURL = req.URL.String()
			}
		}
		status := statusOf(resp)
		return &Finding{
			Check:    "insecure-deserialization",
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("Insecure deserialization (%s) in %s parameter %q", format.label, sink.Loc, sink.Name),
			Detail: fmt.Sprintf(
				"Parameter %q (%s) is fed to a %s deserializer: payload insecure-deserialization/%s "+
					"(wire value %q) provoked deserializer error signature %q in the response. If an attacker "+
					"can construct a gadget chain whose constructor or readObject hook has side-effects, this "+
					"primitive lifts to remote code execution.",
				sink.Name, sink.Loc, format.label, format.name, format.probePayload, newHits[0]),
			CWE:   "CWE-502",
			OWASP: "A08:2021 Software and Data Integrity Failures",
			Remediation: "Replace format-native deserialization (Java ObjectInputStream, .NET BinaryFormatter/LosFormatter, " +
				"PHP unserialize, pickle.loads, Marshal.load, node-serialize) with a data-only format such as " +
				"JSON or Protocol Buffers validated against a schema. When format-native deserialization is " +
				"unavoidable, sign the blob with a server-side key (HMAC) and verify the MAC before " +
				"deserializing, and restrict the deserializer's type allowlist (Java: ObjectInputFilter; " +
				".NET: ISerializationBinder; Python: a RestrictedUnpickler).",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     status,
				Snippet:    snippet(body, []byte(newHits[0]), true),
				Exchange:   RecordExchange(req, nil, false, resp, body, truncated),
			},
			DedupeKey: MakeKey("insecure-deserialization", ScopeParam, target, "loc:"+string(sink.Loc), "param:"+sink.Name),
		}, nil
	}
	return nil, nil
}

// send mutates sink with wireValue, dispatches the request, and reads up
// to insecDeserialBodyCap of the body. Mirrors the shape of the SQLi /
// XSS check senders so future merger of the request shells is mechanical.
func (c InsecureDeserialization) send(ctx context.Context, client *httpclient.Client, sink Sink, wireValue string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := sink.MutateRequest(ctx, wireValue)
	if err != nil {
		return nil, nil, nil, false, err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, insecDeserialBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
}

// matchDeserialAll returns every error pattern across every known format
// that appears in body. Used to build the baseline pattern set so the
// per-format probe can compare what the payload added versus what was
// already there.
func matchDeserialAll(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, format := range deserialFormatList {
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

// Compile-time check: InsecureDeserialization satisfies Check.
