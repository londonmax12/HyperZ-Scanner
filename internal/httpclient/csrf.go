package httpclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// CSRFInject describes how a discovered CSRF token is attached to outgoing
// mutating requests.
type CSRFInject int

const (
	// CSRFInjectAuto picks based on what the source page yielded: a hidden
	// input goes back as a form field; a <meta name="csrf-token"> goes back
	// as a request header.
	CSRFInjectAuto CSRFInject = iota
	// CSRFInjectForm adds the token to an application/x-www-form-urlencoded
	// body. Multipart and JSON bodies are left untouched in v1.
	CSRFInjectForm
	// CSRFInjectHeader adds the token to a request header (default
	// X-CSRF-Token; override via CSRFTokenSource.HeaderName).
	CSRFInjectHeader
)

// CSRFFetcher GETs sourceURL and returns the response body. The implementation
// must not recurse through the same Client the CSRFTokenSource is installed
// in - use the underlying *http.Client (sharing the cookie jar) instead.
type CSRFFetcher func(ctx context.Context, sourceURL string) ([]byte, error)

// CSRFTokenSource is a RequestMiddleware that injects a CSRF token into
// outgoing mutating requests (POST/PUT/PATCH/DELETE by default).
//
// On the first triggering request it lazily GETs SourceURL via the
// caller-supplied Fetcher, parses the body for a well-known token carrier
// (hidden inputs named _token / authenticity_token / __RequestVerificationToken
// / csrf_token / csrfmiddlewaretoken, or a <meta name="csrf-token"> tag), and
// caches what it found. Every later mutating request gets the same token in
// the configured location.
//
// Out of scope for v1 (each is a small follow-up):
//   - double-submit cookie tokens (XSRF-TOKEN cookie -> X-XSRF-TOKEN header)
//   - cache invalidation on a 403 from the target
//   - rewriting multipart or JSON request bodies
type CSRFTokenSource struct {
	SourceURL string
	Fetcher   CSRFFetcher
	// Mode picks the injection style. Defaults to CSRFInjectAuto when zero,
	// which uses Header for meta-tag tokens and Form for hidden-input tokens.
	Mode CSRFInject
	// HeaderName overrides the request-header name used in Header mode.
	// Empty means X-CSRF-Token.
	HeaderName string
	// FieldName overrides the form-field name used in Form mode. Empty means
	// "use whatever name the parsed input element carried" (the common case).
	FieldName string
	// Methods is the set of HTTP methods that trigger injection. Nil uses
	// the default set: POST, PUT, PATCH, DELETE.
	Methods map[string]struct{}

	once     sync.Once
	name     string
	value    string
	mode     CSRFInject
	headerNm string
	fetchErr error
}

// DefaultCSRFHeader is the header CSRFInjectHeader uses when HeaderName is
// empty. It matches the convention emitted by Rails / Spring / Django when
// they advertise the token via <meta name="csrf-token">.
const DefaultCSRFHeader = "X-CSRF-Token"

var defaultCSRFMethods = map[string]struct{}{
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodPatch:  {},
	http.MethodDelete: {},
}

// Before fires the fetcher on the first matching request, caches the parsed
// token, and injects it into every subsequent mutating request. Non-mutating
// requests pass through untouched.
func (s *CSRFTokenSource) Before(req *http.Request) error {
	methods := s.Methods
	if methods == nil {
		methods = defaultCSRFMethods
	}
	if _, ok := methods[strings.ToUpper(req.Method)]; !ok {
		return nil
	}
	s.once.Do(func() { s.fetchOnce(req.Context()) })
	if s.fetchErr != nil {
		return s.fetchErr
	}
	if s.value == "" {
		return nil
	}
	switch s.mode {
	case CSRFInjectHeader:
		req.Header.Set(s.headerNm, s.value)
	case CSRFInjectForm:
		return injectFormField(req, s.name, s.value)
	}
	return nil
}

func (s *CSRFTokenSource) fetchOnce(ctx context.Context) {
	if s.Fetcher == nil {
		s.fetchErr = fmt.Errorf("csrf: no fetcher configured")
		return
	}
	body, err := s.Fetcher(ctx, s.SourceURL)
	if err != nil {
		s.fetchErr = fmt.Errorf("csrf: fetch %s: %w", s.SourceURL, err)
		return
	}
	name, value, kind := ParseCSRFToken(body)
	if name == "" {
		s.fetchErr = fmt.Errorf("csrf: no token found at %s", s.SourceURL)
		return
	}
	mode := s.Mode
	if mode == CSRFInjectAuto {
		if kind == csrfKindMeta {
			mode = CSRFInjectHeader
		} else {
			mode = CSRFInjectForm
		}
	}
	hdr := s.HeaderName
	if mode == CSRFInjectHeader && hdr == "" {
		hdr = DefaultCSRFHeader
	}
	if mode == CSRFInjectForm && s.FieldName != "" {
		name = s.FieldName
	}
	s.name = name
	s.value = value
	s.mode = mode
	s.headerNm = hdr
}

// csrfKind tags how ParseCSRFToken located a token so callers can resolve
// CSRFInjectAuto into a concrete injection mode.
type csrfKind int

const (
	csrfKindNone  csrfKind = 0
	csrfKindInput csrfKind = 1
	csrfKindMeta  csrfKind = 2
)

// csrfInputNames is the closed list of hidden-input names ParseCSRFToken
// recognises. Add to it when extending support to a new framework.
var csrfInputNames = []string{
	"_token",                      // Laravel, generic
	"authenticity_token",          // Rails
	"__RequestVerificationToken",  // ASP.NET MVC / Razor
	"csrf_token",                  // CodeIgniter, Flask-WTF
	"csrfmiddlewaretoken",         // Django
}

// ParseCSRFToken scans the HTML body for the first recognised CSRF token
// carrier and returns its name, value, and which kind of element produced it.
// Returns ("", "", csrfKindNone) if nothing matched.
//
// Recognises:
//   - <input type="hidden" name="<known>"> for the names in csrfInputNames
//   - <meta name="csrf-token" content="...">
//
// Hidden-input wins over meta when both appear, because the input tells you
// the exact field name the server expects in the form body - the meta tag
// only conveys the value.
func ParseCSRFToken(body []byte) (name, value string, kind csrfKind) {
	z := html.NewTokenizer(bytes.NewReader(body))
	var metaName, metaValue string
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		if !hasAttr {
			continue
		}
		switch string(tag) {
		case "input":
			if n, v, ok := matchCSRFInput(z); ok {
				return n, v, csrfKindInput
			}
		case "meta":
			if metaName == "" {
				if n, v, ok := matchCSRFMeta(z); ok {
					metaName, metaValue = n, v
				}
			}
		}
	}
	if metaName != "" {
		return metaName, metaValue, csrfKindMeta
	}
	return "", "", csrfKindNone
}

func matchCSRFInput(z *html.Tokenizer) (string, string, bool) {
	var typeAttr, nameAttr, valueAttr string
	for {
		key, val, more := z.TagAttr()
		switch string(key) {
		case "type":
			typeAttr = string(val)
		case "name":
			nameAttr = string(val)
		case "value":
			valueAttr = string(val)
		}
		if !more {
			break
		}
	}
	if !strings.EqualFold(typeAttr, "hidden") {
		return "", "", false
	}
	for _, n := range csrfInputNames {
		if strings.EqualFold(nameAttr, n) {
			return nameAttr, valueAttr, true
		}
	}
	return "", "", false
}

func matchCSRFMeta(z *html.Tokenizer) (string, string, bool) {
	var nameAttr, contentAttr string
	for {
		key, val, more := z.TagAttr()
		switch string(key) {
		case "name":
			nameAttr = string(val)
		case "content":
			contentAttr = string(val)
		}
		if !more {
			break
		}
	}
	if !strings.EqualFold(nameAttr, "csrf-token") {
		return "", "", false
	}
	return nameAttr, contentAttr, true
}

// injectFormField rewrites an application/x-www-form-urlencoded body to set
// name=value, preserving any existing fields. Bodies of other content types
// (JSON, multipart) are left untouched; the caller can switch to header mode
// for those flows.
func injectFormField(req *http.Request, name, value string) error {
	ct := req.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/x-www-form-urlencoded") {
		return nil
	}
	var raw []byte
	if req.Body != nil {
		full, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return fmt.Errorf("csrf: read form body: %w", err)
		}
		raw = full
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return fmt.Errorf("csrf: parse form body: %w", err)
	}
	values.Set(name, value)
	encoded := []byte(values.Encode())
	req.Body = io.NopCloser(bytes.NewReader(encoded))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(encoded)), nil
	}
	req.ContentLength = int64(len(encoded))
	return nil
}
