package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseCSRFTokenHiddenInput(t *testing.T) {
	cases := []struct {
		name string
		html string
		want string
		val  string
	}{
		{
			name: "Laravel _token",
			html: `<form><input type="hidden" name="_token" value="abc123"></form>`,
			want: "_token", val: "abc123",
		},
		{
			name: "Rails authenticity_token",
			html: `<input type="hidden" name="authenticity_token" value="r4ils-tok" />`,
			want: "authenticity_token", val: "r4ils-tok",
		},
		{
			name: "ASP.NET __RequestVerificationToken",
			html: `<input name="__RequestVerificationToken" type="hidden" value="aspnet-tok"/>`,
			want: "__RequestVerificationToken", val: "aspnet-tok",
		},
		{
			name: "Django csrfmiddlewaretoken",
			html: `<input type="hidden" name="csrfmiddlewaretoken" value="dj-tok">`,
			want: "csrfmiddlewaretoken", val: "dj-tok",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, v, kind := ParseCSRFToken([]byte(tc.html))
			if n != tc.want || v != tc.val {
				t.Fatalf("got name=%q value=%q, want name=%q value=%q", n, v, tc.want, tc.val)
			}
			if kind != csrfKindInput {
				t.Fatalf("kind = %v, want csrfKindInput", kind)
			}
		})
	}
}

func TestParseCSRFTokenMeta(t *testing.T) {
	body := `<html><head><meta name="csrf-token" content="meta-tok-987"></head><body/></html>`
	n, v, kind := ParseCSRFToken([]byte(body))
	if n != "csrf-token" || v != "meta-tok-987" {
		t.Fatalf("got name=%q value=%q, want csrf-token / meta-tok-987", n, v)
	}
	if kind != csrfKindMeta {
		t.Fatalf("kind = %v, want csrfKindMeta", kind)
	}
}

func TestParseCSRFTokenInputBeatsMeta(t *testing.T) {
	body := `<html><head><meta name="csrf-token" content="from-meta"></head>` +
		`<body><form><input type="hidden" name="_token" value="from-input"></form></body></html>`
	n, v, kind := ParseCSRFToken([]byte(body))
	if n != "_token" || v != "from-input" {
		t.Fatalf("got name=%q value=%q, want _token / from-input", n, v)
	}
	if kind != csrfKindInput {
		t.Fatalf("kind = %v, want csrfKindInput", kind)
	}
}

func TestParseCSRFTokenNotFound(t *testing.T) {
	body := `<html><body><form><input type="text" name="q" value="hi"></form></body></html>`
	n, _, kind := ParseCSRFToken([]byte(body))
	if n != "" || kind != csrfKindNone {
		t.Fatalf("got name=%q kind=%v, want empty / csrfKindNone", n, kind)
	}
}

func TestCSRFSkipsNonMutating(t *testing.T) {
	var fetched atomic.Int32
	s := &CSRFTokenSource{
		SourceURL: "http://example.invalid/form",
		Fetcher: func(ctx context.Context, _ string) ([]byte, error) {
			fetched.Add(1)
			return []byte(`<input type="hidden" name="_token" value="x">`), nil
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://t/", nil)
	if err := s.Before(req); err != nil {
		t.Fatalf("GET: %v", err)
	}
	if got := fetched.Load(); got != 0 {
		t.Fatalf("fetcher fired on GET (%d times); should only fire on mutating methods", got)
	}
}

func TestCSRFInjectsFormFieldAndCaches(t *testing.T) {
	var fetched atomic.Int32
	s := &CSRFTokenSource{
		SourceURL: "http://example.invalid/form",
		Fetcher: func(ctx context.Context, _ string) ([]byte, error) {
			fetched.Add(1)
			return []byte(`<input type="hidden" name="_token" value="tok-42">`), nil
		},
	}

	first := newFormPost(t, "name=Alice&age=30")
	if err := s.Before(first); err != nil {
		t.Fatalf("first call: %v", err)
	}
	body := readAndReset(t, first)
	values, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if got := values.Get("_token"); got != "tok-42" {
		t.Fatalf("_token = %q, want tok-42", got)
	}
	if got := values.Get("name"); got != "Alice" {
		t.Fatalf("name = %q, want Alice (original field clobbered)", got)
	}
	if first.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength = %d, want %d", first.ContentLength, len(body))
	}

	// Second mutating request must reuse the cached token without re-fetching.
	second := newFormPost(t, "x=1")
	if err := s.Before(second); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := fetched.Load(); got != 1 {
		t.Fatalf("fetcher fired %d times, want 1 (cached)", got)
	}
}

func TestCSRFInjectsHeaderForMetaToken(t *testing.T) {
	s := &CSRFTokenSource{
		SourceURL: "http://example.invalid/page",
		Fetcher: func(ctx context.Context, _ string) ([]byte, error) {
			return []byte(`<meta name="csrf-token" content="meta-val">`), nil
		},
	}
	req, _ := http.NewRequest(http.MethodPost, "http://t/api", nil)
	if err := s.Before(req); err != nil {
		t.Fatalf("Before: %v", err)
	}
	if got := req.Header.Get(DefaultCSRFHeader); got != "meta-val" {
		t.Fatalf("%s = %q, want meta-val", DefaultCSRFHeader, got)
	}
}

func TestCSRFHonorsExplicitMode(t *testing.T) {
	// Source returns a hidden input, but the operator wants the token sent
	// as a header instead - common for SPAs that POST JSON.
	s := &CSRFTokenSource{
		SourceURL: "http://example.invalid/form",
		Mode:      CSRFInjectHeader,
		Fetcher: func(ctx context.Context, _ string) ([]byte, error) {
			return []byte(`<input type="hidden" name="_token" value="json-tok">`), nil
		},
	}
	req, _ := http.NewRequest(http.MethodPost, "http://t/api", strings.NewReader(`{"hello":"world"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := s.Before(req); err != nil {
		t.Fatalf("Before: %v", err)
	}
	if got := req.Header.Get(DefaultCSRFHeader); got != "json-tok" {
		t.Fatalf("%s = %q, want json-tok", DefaultCSRFHeader, got)
	}
	// JSON body must be untouched.
	body := readAndReset(t, req)
	if body != `{"hello":"world"}` {
		t.Fatalf("body mutated to %q, JSON should be left alone", body)
	}
}

func TestCSRFFetchErrorIsSticky(t *testing.T) {
	var calls atomic.Int32
	boom := errors.New("source page 500")
	s := &CSRFTokenSource{
		SourceURL: "http://example.invalid/form",
		Fetcher: func(ctx context.Context, _ string) ([]byte, error) {
			calls.Add(1)
			return nil, boom
		},
	}
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, "http://t/", nil)
		err := s.Before(req)
		if err == nil || !strings.Contains(err.Error(), "source page 500") {
			t.Fatalf("call %d: err = %v, want wrap of boom", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("fetcher fired %d times, want 1 (error must latch)", got)
	}
}

func TestCSRFFetchSucceedsButNoToken(t *testing.T) {
	s := &CSRFTokenSource{
		SourceURL: "http://example.invalid/form",
		Fetcher: func(ctx context.Context, _ string) ([]byte, error) {
			return []byte(`<html><body>nothing here</body></html>`), nil
		},
	}
	req, _ := http.NewRequest(http.MethodPost, "http://t/", nil)
	err := s.Before(req)
	if err == nil || !strings.Contains(err.Error(), "no token found") {
		t.Fatalf("err = %v, want 'no token found' message", err)
	}
}

func newFormPost(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://t/submit", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = int64(len(body))
	return req
}

func readAndReset(t *testing.T, req *http.Request) string {
	t.Helper()
	if req.Body == nil {
		return ""
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(raw)
}
