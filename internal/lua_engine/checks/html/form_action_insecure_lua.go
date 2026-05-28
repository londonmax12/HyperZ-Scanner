package html

import "net/url"

// This file exposes the form-action-insecure check's helpers to the
// Lua bridge. Sibling to form_action_insecure.go: forwards into the
// package-private parser so the Lua port iterates the same candidate
// list the Go check produces.

// FormActionCandidate is one (action, originating-form) pair the
// form-action-insecure parser produced. Resolved is the absolute URL
// the browser would submit to (after applying any <base href>); Raw
// is the attribute text as the document carried it (kept for the
// per-finding detail). Method is uppercase ("GET" / "POST"). Override
// is true for candidates produced by a <button formaction> or
// <input formaction> rather than the parent <form>'s own action.
// Inputs is the form's input inventory; HasCredentialField records
// whether any input matched the sensitive-name heuristic, so the Lua
// port can branch on severity / title without re-walking the list.
type FormActionCandidate struct {
	Raw                string
	Resolved           string
	Method             string
	Override           bool
	Inputs             []FormActionInput
	HasCredentialField bool
}

// FormActionInput is one named field on the parent form. Sensitive is
// true when name + type triggered the credential-shape heuristic.
type FormActionInput struct {
	Name      string
	Type      string
	Sensitive bool
}

// ScanFormActions walks body once and returns one FormActionCandidate
// per <form action> + per <button formaction> / <input formaction>
// override the document carries. baseURL drives relative resolution
// (and is updated when a <base href> is observed in document order).
// Non-network actions (javascript:, mailto:, fragment, ...) are
// filtered out; the Lua port iterates the remaining candidates and
// emits a finding for each whose Resolved is http://.
func ScanFormActions(body []byte, baseURL string) []FormActionCandidate {
	pageURL, err := url.Parse(baseURL)
	if err != nil || pageURL == nil {
		return nil
	}
	forms, cands := parseFormActions(body, pageURL)
	out := make([]FormActionCandidate, 0, len(cands))
	for _, c := range cands {
		var inputs []FormActionInput
		var hasCred bool
		if c.formIdx >= 0 && c.formIdx < len(forms) {
			for _, in := range forms[c.formIdx].inputs {
				inputs = append(inputs, FormActionInput{
					Name:      in.name,
					Type:      in.typ,
					Sensitive: in.sensitive,
				})
				if in.sensitive {
					hasCred = true
				}
			}
		}
		out = append(out, FormActionCandidate{
			Raw:                c.raw,
			Resolved:           c.resolved.String(),
			Method:             c.method,
			Override:           c.override,
			Inputs:             inputs,
			HasCredentialField: hasCred,
		})
	}
	return out
}
