package lua_engine

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// FormActionInsecure detects <form action=...> (or <button formaction=...> /
// <input formaction=...> overrides) that resolve to a plaintext http:// URL
// when the containing page is served over HTTPS. Any field the user submits
// (passwords, session tokens, payment data, PII) is then transmitted in
// cleartext and is trivially recoverable by anyone on the network path,
// even though the page that hosted the form looked secure.
//
// Severity escalates to Critical when the affected form carries a password
// input or another credential-shaped field (name matches "password" /
// "pwd" / "secret" / "card" / etc.). A vanilla HTTPS->HTTP submit without
// credentials stays High because the leak surface is smaller but still
// real (session cookies, CSRF tokens, free-form PII).
type FormActionInsecure struct{}

// sensitiveFieldNamePatterns is a lower-cased substring set against which
// <input name=...> values are matched to detect credential-shaped fields.
// Hit semantics are conservative: matching any one of these bumps the
// finding from High to Critical because what the form leaks shifts from
// "session-data over plaintext" to "password / payment-data over plaintext".
var sensitiveFieldNamePatterns = []string{
	"password", "passwd", "pwd",
	"secret",
	"token", "apikey", "api_key",
	"card", "cvv", "cvc",
	"ssn", "passport",
	"pin",
}

// formCandidate is one (action, originating-form) pair the check should
// evaluate. A document with one <form> + two <button formaction=...> overrides
// produces three candidates - the form's own action plus one per override -
// each carrying back-reference to the parent form so severity / detail can
// inspect the same input set.
type formCandidate struct {
	// raw is the attribute value as it appeared in the document - "/login",
	// "http://x/", etc. - kept for the evidence string.
	raw string
	// resolved is the absolute URL the browser would submit to, after
	// applying the page URL and any <base href>.
	resolved *url.URL
	// method is uppercase ("GET" or "POST"); falls back to GET when the
	// attribute is missing, matching browser default.
	method string
	// override marks candidates that came from a <button formaction> /
	// <input formaction> rather than the parent <form>'s action.
	override bool
	// formIdx indexes into the document's form list so the finding builder
	// can re-read the form's input inventory.
	formIdx int
}

// parsedForm is the input inventory the tokenizer captured for one <form>.
// We track it separately from formCandidate so multiple candidates (the
// form's own action plus formaction overrides) can share the same inputs.
type parsedForm struct {
	inputs []formInput
}

type formInput struct {
	name      string
	typ       string
	sensitive bool
}

// parse walks the document once, collecting the input inventory per <form>
// and emitting one formCandidate for the form's own action plus one for
// each <button formaction=...> / <input formaction=...> override. baseURL
// (initialized to pageURL) is updated when a <base href="..."> is observed
// so relative actions resolve against the document base rather than the
// page URL when an explicit base is in play.
func (c FormActionInsecure) parse(body []byte, pageURL *url.URL) ([]parsedForm, []formCandidate) {
	z := html.NewTokenizer(bytes.NewReader(body))

	baseURL := *pageURL
	baseURLPtr := &baseURL

	var forms []parsedForm
	var candidates []formCandidate

	// inForm tracks the form we are currently inside; -1 when outside any
	// <form>. HTML disallows nested forms, but a malformed document might
	// still try; we treat the outer form's open as still-in-effect and
	// ignore inner <form> opens.
	inForm := -1

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken && tt != html.EndTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		tagName := string(tag)

		switch tagName {
		case "base":
			if tt == html.EndTagToken {
				continue
			}
			if href := attrValue(z, hasAttr, "href"); href != "" {
				if u, err := url.Parse(strings.TrimSpace(href)); err == nil {
					baseURLPtr = baseURL.ResolveReference(u)
				}
			}

		case "form":
			if tt == html.EndTagToken {
				inForm = -1
				continue
			}
			form, action, actionPresent, method := readFormStart(z, hasAttr)
			inForm = len(forms)
			forms = append(forms, form)

			if !actionPresent || strings.TrimSpace(action) == "" {
				// Missing or empty action submits to the current page URL,
				// which is HTTPS (the caller short-circuited otherwise).
				continue
			}
			resolved, ok := resolveAction(action, baseURLPtr)
			if !ok {
				continue
			}
			candidates = append(candidates, formCandidate{
				raw:      action,
				resolved: resolved,
				method:   method,
				override: false,
				formIdx:  inForm,
			})

		case "input":
			if tt == html.EndTagToken {
				continue
			}
			if inForm < 0 {
				continue
			}
			name, typ, formaction, formmethod := readFormSubmittable(z, hasAttr)
			if name != "" {
				forms[inForm].inputs = append(forms[inForm].inputs, formInput{
					name:      name,
					typ:       typ,
					sensitive: isSensitiveField(name, typ),
				})
			}
			// formaction on <input> only meaningful for submit/image types.
			if formaction != "" && (typ == "submit" || typ == "image") {
				appendFormactionCandidate(&candidates, formaction, formmethod, baseURLPtr, inForm)
			}

		case "button":
			if tt == html.EndTagToken {
				continue
			}
			if inForm < 0 {
				continue
			}
			typ, formaction, formmethod := readButtonStart(z, hasAttr)
			// HTML default button type inside a form is "submit". Treat
			// missing/empty type as submit; only skip explicit non-submits.
			if typ != "" && typ != "submit" {
				continue
			}
			if formaction != "" {
				appendFormactionCandidate(&candidates, formaction, formmethod, baseURLPtr, inForm)
			}

		case "textarea", "select":
			if tt == html.EndTagToken {
				continue
			}
			if inForm < 0 {
				continue
			}
			if name := attrValue(z, hasAttr, "name"); name != "" {
				forms[inForm].inputs = append(forms[inForm].inputs, formInput{
					name:      name,
					typ:       tagName,
					sensitive: isSensitiveField(name, tagName),
				})
			}
		}
	}
	return forms, candidates
}

// readFormStart pulls action / method / id from a <form> start tag.
// Reports actionPresent so callers can distinguish "no action attribute"
// (submits to self) from action="" (also submits to self, browser quirk).
func readFormStart(z *html.Tokenizer, hasAttr bool) (form parsedForm, action string, actionPresent bool, method string) {
	method = "GET"
	if !hasAttr {
		return parsedForm{}, "", false, method
	}
	for {
		key, val, more := z.TagAttr()
		switch strings.ToLower(string(key)) {
		case "action":
			action = string(val)
			actionPresent = true
		case "method":
			m := strings.ToUpper(strings.TrimSpace(string(val)))
			if m == "POST" {
				method = "POST"
			}
		}
		if !more {
			break
		}
	}
	return parsedForm{}, action, actionPresent, method
}

// readFormSubmittable pulls name / type / formaction / formmethod from an
// <input> tag. formaction only matters for submit/image inputs; the caller
// applies that filter.
func readFormSubmittable(z *html.Tokenizer, hasAttr bool) (name, typ, formaction, formmethod string) {
	typ = "text"
	if !hasAttr {
		return "", typ, "", ""
	}
	for {
		key, val, more := z.TagAttr()
		switch strings.ToLower(string(key)) {
		case "name":
			name = string(val)
		case "type":
			typ = strings.ToLower(strings.TrimSpace(string(val)))
		case "formaction":
			formaction = string(val)
		case "formmethod":
			formmethod = strings.ToUpper(strings.TrimSpace(string(val)))
		}
		if !more {
			break
		}
	}
	return name, typ, formaction, formmethod
}

// readButtonStart pulls type / formaction / formmethod from a <button> tag.
func readButtonStart(z *html.Tokenizer, hasAttr bool) (typ, formaction, formmethod string) {
	if !hasAttr {
		return "", "", ""
	}
	for {
		key, val, more := z.TagAttr()
		switch strings.ToLower(string(key)) {
		case "type":
			typ = strings.ToLower(strings.TrimSpace(string(val)))
		case "formaction":
			formaction = string(val)
		case "formmethod":
			formmethod = strings.ToUpper(strings.TrimSpace(string(val)))
		}
		if !more {
			break
		}
	}
	return typ, formaction, formmethod
}

// attrValue scans the current tag's attributes for the named one and
// returns its value. Returns "" when the attribute is absent.
func attrValue(z *html.Tokenizer, hasAttr bool, want string) string {
	if !hasAttr {
		return ""
	}
	want = strings.ToLower(want)
	for {
		key, val, more := z.TagAttr()
		if strings.ToLower(string(key)) == want {
			return string(val)
		}
		if !more {
			return ""
		}
	}
}

// resolveAction returns the absolute URL the browser would submit to, or
// (nil, false) for non-network actions (javascript:, mailto:, tel:, data:,
// fragment-only). Resolution applies baseURL (which may be the page URL
// itself, or a <base href> override).
func resolveAction(raw string, baseURL *url.URL) (*url.URL, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "#") {
		return nil, false
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, false
	}
	return baseURL.ResolveReference(parsed), true
}

// appendFormactionCandidate is the shared tail used by <button formaction>
// and <input type=submit formaction> handling. formmethod overrides the
// parent form's method when present (HTML5 behavior). Skips non-network
// schemes so a "javascript:" override doesn't fan out as a finding.
func appendFormactionCandidate(out *[]formCandidate, raw, formmethod string, baseURL *url.URL, formIdx int) {
	resolved, ok := resolveAction(raw, baseURL)
	if !ok {
		return
	}
	method := "GET"
	if formmethod == "POST" {
		method = "POST"
	}
	*out = append(*out, formCandidate{
		raw:      raw,
		resolved: resolved,
		method:   method,
		override: true,
		formIdx:  formIdx,
	})
}

// isSensitiveField applies a type-first, name-fallback heuristic mirroring
// the one in form-autocomplete: any type="password" input is sensitive
// regardless of name, and any other input whose name substring-matches a
// known credential-shaped pattern is treated as sensitive.
func isSensitiveField(name, typ string) bool {
	if typ == "password" {
		return true
	}
	lower := strings.ToLower(name)
	for _, pat := range sensitiveFieldNamePatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

