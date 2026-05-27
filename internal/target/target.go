// Package target describes one unit of work the scanner moves through its
// dispatch queue. A Target generalizes the pre-worklist single-Page model:
// the same dispatch path can carry crawled HTML pages, API endpoints
// surfaced by a discovery check, a specific (page, parameter) input
// surface, or a bare host that still needs fingerprinting.
//
// Targets are canonical-key dedupable so a discovery emission that
// re-surfaces an already-known surface collapses into the existing queued
// item rather than re-dispatching every check against it. The key folds
// case-insensitive scheme/host, strips fragment, normalizes method, and
// includes any per-kind discriminators (param name + location, endpoint
// content-type family) so two pushes that describe the same scan unit
// produce the same key.
//
// This package is intentionally light on engine semantics: the worklist
// owns dedupe, scope filtering, tier ordering, and budgets. Target is the
// payload, not the policy.
package target

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/londonmax12/hyperz/internal/fingerprint"
)

// Kind classifies what a Target represents to the dispatcher. The
// constants are spaced so future intermediate kinds (e.g. KindHeader for
// a header-only surface) can slot in without renumbering.
type Kind int

const (
	// KindHost is a bare scheme://host that has not yet been
	// fingerprinted. The fingerprint tier consumes these and lifts the
	// detected Stack onto subsequent same-host targets.
	KindHost Kind = iota + 1

	// KindPage is a crawled URL with a fetched response (status, headers,
	// body, forms). The pre-worklist scanner emitted exactly this; every
	// page from the crawler enters the queue as a KindPage.
	KindPage

	// KindEndpoint is an API endpoint a discovery check surfaced (method
	// + URL + content-type, optionally with an auth or sample-body hint).
	// Distinct from KindPage because the discriminator includes Method
	// and ContentType: POST /api/login and GET /api/login are different
	// units of work even though their URL matches.
	KindEndpoint

	// KindParam is a (page-or-endpoint, parameter-name, location) tuple
	// scoped to a specific input. Used by checks that fan out per-input
	// rather than per-URL, and by discovery emissions that surface a
	// newly-found parameter on an already-known surface.
	KindParam
)

// String returns the lowercased label used in canonical keys and logs.
// Unknown kinds render as kind(N) so a misuse surfaces visibly rather
// than colliding with a real label.
func (k Kind) String() string {
	switch k {
	case KindHost:
		return "host"
	case KindPage:
		return "page"
	case KindEndpoint:
		return "endpoint"
	case KindParam:
		return "param"
	default:
		return fmt.Sprintf("kind(%d)", int(k))
	}
}

// Target is one scan-dispatch unit. Construct via the kind-specific
// helpers (Page, Endpoint, Param, Host) rather than literal struct
// initialization so the invariants the dispatcher relies on stay in
// one place.
//
// Origin labels where the target came from: "crawler" for pages the
// crawler emitted, "check:<name>" for discoveries emitted by a check,
// "phase2" for re-fetched targets the legacy two-phase orchestration
// surfaces. The dispatcher uses Origin for self-loop break (a check
// never receives the discovery it emitted) and for budget accounting
// (cross-host discoveries debit the emitter's host budget, not the
// destination's).
//
// Parent is the canonical key of the target that produced this one via
// discovery emission. Empty for crawler-origin targets. Used together
// with Origin to detect direct self-loops.
//
// Note is opaque text the producing check can carry forward to its own
// re-dispatch (e.g. a stored-XSS readback marker keyed on a planted
// canary token). The dispatcher does not interpret Note and does not
// fold it into the canonical key; two pushes with identical fields but
// different Note values still dedupe.
//
// Stack is populated by the dispatcher after the host-fingerprint tier
// runs against this target's host. Checks read it via core.StackFrom
// instead of consulting Target.Stack directly; the field exists so the
// dispatcher does not pay a second fingerprint-cache lookup per check.
type Target struct {
	Kind          Kind
	URL           string
	Method        string
	ContentType   string
	Param         string
	ParamLocation string
	Origin        string
	Parent        string
	Note          string
	Stack         *fingerprint.Stack
}

// CanonicalKey returns the dedupe identifier for t. Two pushes that
// describe the same scan unit produce the same key; the worklist uses
// it to collapse re-emissions.
//
// The key folds: lowercased kind label, uppercased method, fragment-
// stripped lowercased-host URL, param-name + param-location (for
// KindParam), and content-type family (for KindEndpoint). Note and
// Origin are NOT folded in: the same surface re-discovered by a
// different check, or carrying a different opaque note, is still the
// same surface and should collapse.
//
// An unparseable URL falls back to the raw string so malformed inputs
// dedupe against themselves rather than collapsing to a single empty
// key.
func (t Target) CanonicalKey() string {
	canon := canonicalizeURL(t.URL)
	method := strings.ToUpper(strings.TrimSpace(t.Method))
	parts := []string{t.Kind.String(), method, canon}
	switch t.Kind {
	case KindEndpoint:
		parts = append(parts, contentTypeFamily(t.ContentType))
	case KindParam:
		parts = append(parts, t.Param, strings.ToLower(t.ParamLocation))
	}
	return strings.Join(parts, "|")
}

// Host returns the lowercased scheme://host prefix of t.URL, or ""
// when the URL is malformed or hostless. Used by the worklist's
// per-host budget accounting and for grouping discoveries by their
// destination.
func (t Target) Host() string {
	u, err := url.Parse(t.URL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// Page builds a KindPage target with origin. p is the URL string the
// crawler observed; the response data itself rides in the page.Page
// struct the scanner still threads through to scanOne and is not
// duplicated here.
func Page(rawurl, origin string) Target {
	return Target{Kind: KindPage, URL: rawurl, Origin: origin}
}

// Endpoint builds a KindEndpoint target. method is uppercased; an
// empty contentType is fine for surfaces whose request shape is not
// yet known.
func Endpoint(rawurl, method, contentType, origin string) Target {
	return Target{
		Kind:        KindEndpoint,
		URL:         rawurl,
		Method:      strings.ToUpper(method),
		ContentType: contentType,
		Origin:      origin,
	}
}

// Param builds a KindParam target. location is one of "query", "body",
// "header", "cookie", "path"; an unknown location does not error but
// will produce a key distinct from the canonical values.
func Param(rawurl, paramName, location, origin string) Target {
	return Target{
		Kind:          KindParam,
		URL:           rawurl,
		Param:         paramName,
		ParamLocation: strings.ToLower(location),
		Origin:        origin,
	}
}

// Host builds a KindHost target. Used by the fingerprint tier; checks
// downstream of the tier consume KindPage / KindEndpoint targets that
// already carry the detected Stack.
func Host(rawurl, origin string) Target {
	return Target{Kind: KindHost, URL: rawurl, Origin: origin}
}

// canonicalizeURL strips fragment, lowercases the host, and returns the
// resulting string. Malformed inputs are returned verbatim so the dedupe
// map does not collapse every malformed URL to the same key.
func canonicalizeURL(rawurl string) string {
	if rawurl == "" {
		return ""
	}
	u, err := url.Parse(rawurl)
	if err != nil || u.Host == "" {
		return rawurl
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// contentTypeFamily strips parameters from a Content-Type and
// lowercases the result. "text/html; charset=utf-8" -> "text/html".
// Empty input returns "" so the worklist's dedupe key does not depend
// on whether an endpoint discovery happened to know its content type
// up front.
func contentTypeFamily(ct string) string {
	if ct == "" {
		return ""
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}
