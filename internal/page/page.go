// Package page describes the artifact the crawler hands to checks: one
// observed URL plus the response that observation produced.
//
// A check should read page.Headers / page.Body / page.Forms instead of
// re-fetching the URL itself - on a 200-page crawl with 5 passive checks
// that previously each issued their own GET, this cuts request count by
// ~5x. Active checks (open-redirect, future XSS/SQLi/CSRF) use page.URL
// as their target and craft fresh requests via the http client; page.Forms
// is the structured input surface they fuzz over.
package page

import (
	"net/http"
	"net/url"
)

// Page is one URL the crawler (or no-crawl feeder) observed.
//
// Body is whatever the producer buffered, capped at the producer's
// MaxBodyBytes. It is nil when the response had no body, when the body
// exceeded the cap, or when reading failed; nil body is not proof the
// resource was empty. Forms is populated only when Body was an HTML
// document - non-HTML responses carry nil Forms even when Body is set.
//
// Fetched signals "a producer already attempted the HTTP request for this
// URL." The crawler sets it on every page it emits, including the
// connect-failed / read-failed paths where Headers stays nil. Downstream
// helpers (checks/ensureResponse) use it to distinguish a never-tried
// page (no-crawl seed, page.FromURL in tests) - which they should fetch -
// from a known-failed page they should skip, so a down host doesn't get
// re-probed once per passive check.
type Page struct {
	URL     string
	Status  int
	Headers http.Header
	Body    []byte
	Forms   []Form
	Fetched bool
	// SpecOps is the input surface the crawler harvested from an OpenAPI
	// or Swagger document whose `paths` resolved to this URL. Crawl emits
	// one Page per fetched URL, but a spec may describe multiple HTTP
	// methods (GET + POST + ...) at the same URL with different inputs;
	// all of them ride here so input-fuzzing checks can fan out per
	// operation. Empty for pages discovered by crawling HTML.
	SpecOps []SpecOp
}

// Form captures one <form> element discovered on a page.
//
// Method is uppercase ("GET" or "POST"; HTML's default is GET when the
// attribute is missing or unrecognized). Action is resolved to an absolute
// http(s) URL against the page's URL; forms with an unresolvable action
// are returned with Action empty so callers can decide whether to skip.
// Inputs is every named control inside the form so input-fuzzing checks
// can iterate over fields without re-parsing HTML.
type Form struct {
	Method string
	Action string
	Inputs []FormInput
}

// FormInput is one named control extracted from a <form>. Name is the
// HTML `name` attribute (controls without a name are skipped since the
// browser won't submit them). Type is the lowercased HTML `type` for
// <input>; for non-input elements it's the tag name ("select", "textarea",
// "button"). Value is the default value the browser would submit; empty
// is fine and common, since checks supply their own payload anyway.
type FormInput struct {
	Name  string
	Type  string
	Value string
}

// SpecOp is one OpenAPI / Swagger operation whose request URL the
// crawler also planned to fetch. Method is uppercase (GET / POST / ...).
// URL is the request URL with all `{param}` path placeholders filled to
// "1" - the same form Page.URL takes after the crawler submits it. Tpl
// is the original path-templated URL with `{name}` placeholders still
// present, used by input-fuzzing checks so a path-parameter probe can
// substitute its own value into the right segment.
//
// Params is the inventory of named inputs the spec declared for this
// operation: query, path, header, cookie, and body (JSON or form). It
// is what `checks.SinksFor` mines to produce sinks beyond the query
// and form surface visible from HTML alone.
type SpecOp struct {
	Method string
	URL    string
	Tpl    string
	Params []SpecParam
}

// SpecParam is one named input on a SpecOp. In matches the OpenAPI
// `in:` field ("query", "path", "header", "cookie", "body", "formData")
// and is left as-is so callers can apply their own Loc mapping. Name is
// the parameter name; for body params (in: body / formData) it's the
// top-level JSON / form field name extracted from the schema, not the
// schema name. Value is an example or default value if the spec gave
// one, "" otherwise.
type SpecParam struct {
	In    string
	Name  string
	Value string
}

// ParsedURL returns the parsed URL or nil if Page.URL is malformed. A
// convenience for checks that need scheme/host/path/query without
// re-importing net/url just for one call.
func (p Page) ParsedURL() *url.URL {
	u, err := url.Parse(p.URL)
	if err != nil {
		return nil
	}
	return u
}

// FromURL builds a Page carrying only a URL - useful in tests and in any
// caller path where the response hasn't been fetched yet. Checks that
// need Headers/Body must tolerate them being nil/empty; production
// pipelines fill them in via the crawler or no-crawl feeder.
func FromURL(rawurl string) Page {
	return Page{URL: rawurl}
}
