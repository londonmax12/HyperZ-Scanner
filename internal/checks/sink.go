package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/londonball/hyperz/internal/page"
)

// Loc identifies where on the wire a user-influenced value rides. Two
// inputs with the same Name but different Loc are distinct sinks - a
// query param `id` and a JSON field `id` are different attack surfaces.
type Loc string

const (
	LocQuery  Loc = "query"  // URL query parameter
	LocForm   Loc = "form"   // application/x-www-form-urlencoded body field
	LocHeader Loc = "header" // request header
	LocCookie Loc = "cookie" // Cookie header value
	LocJSON   Loc = "json"   // JSON body field (reserved; not yet built)
	LocPath   Loc = "path"   // path segment (reserved; not yet built)
)

// Sink is one user-influenced input on a target HTTP request. Input-
// fuzzing checks (open-redirect today; XSS / SQLi / SSRF / CSRF / IDOR
// next) iterate over Sinks and overwrite one at a time with a probe
// payload via MutateRequest. The abstraction exists so each new check
// doesn't reinvent "what inputs does this URL have" - SinksFor is the
// single source of truth.
//
// Method is uppercase HTTP method (GET / POST / ...). URL is the
// absolute target the request will be sent to. Value is the original
// value the page carried for this input, retained for evidence and for
// reflection-based probes that need to know what the app already saw;
// MutateRequest overwrites it on the wire.
type Sink struct {
	Method string
	URL    string
	Loc    Loc
	Name   string
	Value  string
}

// SinksFor returns every fuzz-able input visible on p:
//   - one Sink per query parameter on p.URL (Method=GET, Loc=Query)
//   - for each form in p.Forms, one Sink per named input (Method=
//     form.Method, URL=form.Action, Loc=Query for GET / Form for POST)
//
// Output is deterministic: sinks are deduped on (Method, URL, Loc,
// Name) and sorted, so probe order stays stable across runs and a
// param that appears as both a URL query and a form field is one Sink,
// not two. JSON / path / cookie / header sinks aren't produced yet -
// the page artifact doesn't carry them, and the checks that need them
// haven't been built.
func SinksFor(p page.Page) []Sink {
	type key struct {
		method string
		url    string
		loc    Loc
		name   string
	}
	seen := map[key]int{}
	var out []Sink

	add := func(s Sink) {
		if s.Name == "" || s.URL == "" {
			return
		}
		k := key{s.Method, s.URL, s.Loc, s.Name}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = len(out)
		out = append(out, s)
	}

	if u, err := url.Parse(p.URL); err == nil {
		// Iterate query keys in sorted order so dedupe is deterministic
		// even when the page is processed multiple times.
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := ""
			if vs := q[k]; len(vs) > 0 {
				v = vs[0]
			}
			add(Sink{Method: http.MethodGet, URL: p.URL, Loc: LocQuery, Name: k, Value: v})
		}
	}

	for _, f := range p.Forms {
		method := strings.ToUpper(f.Method)
		if method == "" {
			method = http.MethodGet
		}
		loc := LocQuery
		if method == http.MethodPost {
			loc = LocForm
		}
		for _, in := range f.Inputs {
			add(Sink{Method: method, URL: f.Action, Loc: loc, Name: in.Name, Value: in.Value})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		if out[i].Loc != out[j].Loc {
			return out[i].Loc < out[j].Loc
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// MutateRequest builds an *http.Request for s with s.Name overwritten by
// payload. Other inputs on the target request keep their original values
// where they're known so the request still authenticates and routes the
// way the app expects.
//
// LocQuery overlays payload onto the named param of s.URL, preserving
// other query params. LocForm builds an x-www-form-urlencoded body
// carrying payload under s.Name (other form fields are not preserved -
// the caller would have to merge them in via Sink.Value as future
// checks need that). LocHeader sets the named header. LocCookie adds a
// single Cookie header. LocJSON and LocPath are not implemented yet
// and return an error so callers fail loudly instead of silently
// skipping coverage.
func (s Sink) MutateRequest(ctx context.Context, payload string) (*http.Request, error) {
	method := strings.ToUpper(s.Method)
	if method == "" {
		method = http.MethodGet
	}
	switch s.Loc {
	case LocQuery:
		u, err := url.Parse(s.URL)
		if err != nil {
			return nil, fmt.Errorf("parse url %q: %w", s.URL, err)
		}
		q := u.Query()
		q.Set(s.Name, payload)
		u.RawQuery = q.Encode()
		return http.NewRequestWithContext(ctx, method, u.String(), nil)
	case LocForm:
		body := url.Values{}
		body.Set(s.Name, payload)
		req, err := http.NewRequestWithContext(ctx, method, s.URL, strings.NewReader(body.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	case LocHeader:
		req, err := http.NewRequestWithContext(ctx, method, s.URL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set(s.Name, payload)
		return req, nil
	case LocCookie:
		req, err := http.NewRequestWithContext(ctx, method, s.URL, nil)
		if err != nil {
			return nil, err
		}
		req.AddCookie(&http.Cookie{Name: s.Name, Value: payload})
		return req, nil
	case LocJSON, LocPath:
		return nil, fmt.Errorf("sink loc %q is not yet wired", s.Loc)
	default:
		return nil, fmt.Errorf("unknown sink loc %q", s.Loc)
	}
}

