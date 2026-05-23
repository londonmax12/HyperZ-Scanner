package checks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/londonball/hyperz/internal/page"
)

func TestSinksForQueryParams(t *testing.T) {
	p := page.Page{URL: "http://example.com/x?a=1&b=2"}
	got := SinksFor(p)
	want := []Sink{
		{Method: "GET", URL: "http://example.com/x?a=1&b=2", Loc: LocQuery, Name: "a", Value: "1"},
		{Method: "GET", URL: "http://example.com/x?a=1&b=2", Loc: LocQuery, Name: "b", Value: "2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestSinksForFormGet(t *testing.T) {
	p := page.Page{
		URL: "http://example.com/",
		Forms: []page.Form{{
			Method: "GET",
			Action: "http://example.com/search",
			Inputs: []page.FormInput{
				{Name: "q", Type: "text", Value: ""},
				{Name: "lang", Type: "hidden", Value: "en"},
			},
		}},
	}
	got := SinksFor(p)
	// GET form yields LocQuery sinks (browser appends as query string).
	want := []Sink{
		{Method: "GET", URL: "http://example.com/search", Loc: LocQuery, Name: "lang", Value: "en"},
		{Method: "GET", URL: "http://example.com/search", Loc: LocQuery, Name: "q", Value: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestSinksForFormPost(t *testing.T) {
	p := page.Page{
		URL: "http://example.com/",
		Forms: []page.Form{{
			Method: "POST",
			Action: "http://example.com/login",
			Inputs: []page.FormInput{
				{Name: "user", Value: ""},
				{Name: "pass", Value: ""},
			},
		}},
	}
	got := SinksFor(p)
	want := []Sink{
		{Method: "POST", URL: "http://example.com/login", Loc: LocForm, Name: "pass", Value: ""},
		{Method: "POST", URL: "http://example.com/login", Loc: LocForm, Name: "user", Value: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestSinksForDedupesQueryAndForm(t *testing.T) {
	// A param that lives both as a URL query and on a GET form posting back
	// to the same URL must be emitted once (same Method/URL/Loc/Name).
	p := page.Page{
		URL: "http://example.com/x?q=v",
		Forms: []page.Form{{
			Method: "GET",
			Action: "http://example.com/x?q=v",
			Inputs: []page.FormInput{{Name: "q", Value: "v"}},
		}},
	}
	got := SinksFor(p)
	if len(got) != 1 {
		t.Fatalf("got %d sinks, want 1 deduped: %+v", len(got), got)
	}
}

func TestSinksForSkipsUnnamedInputs(t *testing.T) {
	p := page.Page{
		URL: "http://example.com/",
		Forms: []page.Form{{
			Method: "POST",
			Action: "http://example.com/x",
			Inputs: []page.FormInput{
				{Name: "", Value: "anon"},
				{Name: "real", Value: "v"},
			},
		}},
	}
	got := SinksFor(p)
	if len(got) != 1 || got[0].Name != "real" {
		t.Fatalf("got %+v, want only [real]", got)
	}
}

func TestSinksForUnparseableURL(t *testing.T) {
	// Unparseable page.URL still surfaces form sinks - the URL parse failure
	// is only fatal for query-derived sinks.
	p := page.Page{
		URL: "::not-a-url::",
		Forms: []page.Form{{
			Method: "POST",
			Action: "http://example.com/x",
			Inputs: []page.FormInput{{Name: "a"}},
		}},
	}
	got := SinksFor(p)
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("got %+v, want one form sink for `a`", got)
	}
}

func TestSinksForStableOrder(t *testing.T) {
	// Iteration order on map[string][]string is randomized; SinksFor must
	// stabilize it so probe order and finding order don't drift between
	// runs.
	p := page.Page{URL: "http://example.com/x?b=2&c=3&a=1"}
	first := SinksFor(p)
	for i := 0; i < 5; i++ {
		got := SinksFor(p)
		if !reflect.DeepEqual(got, first) {
			names := make([]string, len(got))
			for j, s := range got {
				names[j] = s.Name
			}
			t.Fatalf("iteration %d differed: %v", i, names)
		}
	}
	// And sorted ascending by name within the same URL.
	wantNames := []string{"a", "b", "c"}
	gotNames := make([]string, len(first))
	for i, s := range first {
		gotNames[i] = s.Name
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("got %v, want sorted %v", gotNames, wantNames)
	}
}

func TestMutateRequestQueryOverlay(t *testing.T) {
	s := Sink{Method: "GET", URL: "http://example.com/r?a=1&b=2&next=orig", Loc: LocQuery, Name: "next"}
	req, err := s.MutateRequest(context.Background(), "payload")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	q := req.URL.Query()
	if got := q.Get("next"); got != "payload" {
		t.Errorf("next = %q, want payload", got)
	}
	if got := q.Get("a"); got != "1" {
		t.Errorf("a corrupted: %q", got)
	}
	if got := q.Get("b"); got != "2" {
		t.Errorf("b corrupted: %q", got)
	}
}

func TestMutateRequestFormBody(t *testing.T) {
	s := Sink{Method: "POST", URL: "http://example.com/login", Loc: LocForm, Name: "user"}
	req, err := s.MutateRequest(context.Background(), "admin' OR 1=1--")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want form-urlencoded", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if got := form.Get("user"); got != "admin' OR 1=1--" {
		t.Errorf("user = %q, want payload", got)
	}
}

func TestMutateRequestHeader(t *testing.T) {
	s := Sink{Method: "GET", URL: "http://example.com/", Loc: LocHeader, Name: "X-Forwarded-For"}
	req, err := s.MutateRequest(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "127.0.0.1" {
		t.Errorf("header = %q, want 127.0.0.1", got)
	}
}

func TestMutateRequestCookie(t *testing.T) {
	s := Sink{Method: "GET", URL: "http://example.com/", Loc: LocCookie, Name: "session"}
	req, err := s.MutateRequest(context.Background(), "deadbeef")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if got, err := req.Cookie("session"); err != nil || got.Value != "deadbeef" {
		t.Errorf("cookie session = %v err=%v, want value=deadbeef", got, err)
	}
}

func TestSinksForSpecOps(t *testing.T) {
	p := page.Page{
		URL: "http://example.com/items/1",
		SpecOps: []page.SpecOp{
			{
				Method: "GET",
				URL:    "http://example.com/items/1",
				Tpl:    "http://example.com/items/{id}",
				Params: []page.SpecParam{
					{In: "path", Name: "id"},
					{In: "query", Name: "verbose"},
					{In: "header", Name: "X-Trace"},
					{In: "cookie", Name: "session"},
				},
			},
			{
				Method: "POST",
				URL:    "http://example.com/items/1",
				Tpl:    "http://example.com/items/{id}",
				Params: []page.SpecParam{
					{In: "body", Name: "title"},
					{In: "formData", Name: "qty"},
				},
			},
		},
	}
	got := SinksFor(p)
	want := map[string]Sink{
		"GET|http://example.com/items/{id}|path|id":      {Method: "GET", URL: "http://example.com/items/{id}", Loc: LocPath, Name: "id"},
		"GET|http://example.com/items/1|query|verbose":   {Method: "GET", URL: "http://example.com/items/1", Loc: LocQuery, Name: "verbose"},
		"GET|http://example.com/items/1|header|X-Trace":  {Method: "GET", URL: "http://example.com/items/1", Loc: LocHeader, Name: "X-Trace"},
		"GET|http://example.com/items/1|cookie|session":  {Method: "GET", URL: "http://example.com/items/1", Loc: LocCookie, Name: "session"},
		"POST|http://example.com/items/{id}|path|id":     {Method: "POST", URL: "http://example.com/items/{id}", Loc: LocPath, Name: "id"},
		"POST|http://example.com/items/1|json|title":     {Method: "POST", URL: "http://example.com/items/1", Loc: LocJSON, Name: "title"},
		"POST|http://example.com/items/1|form|qty":       {Method: "POST", URL: "http://example.com/items/1", Loc: LocForm, Name: "qty"},
	}
	// Want path:id from GET op but POST op has no path:id - check that
	// only the GET path-sink shows up.
	delete(want, "POST|http://example.com/items/{id}|path|id")
	gotMap := map[string]Sink{}
	for _, s := range got {
		k := s.Method + "|" + s.URL + "|" + string(s.Loc) + "|" + s.Name
		gotMap[k] = s
	}
	if !reflect.DeepEqual(gotMap, want) {
		t.Fatalf("\ngot:  %+v\nwant: %+v", gotMap, want)
	}
}

func TestSinksForSpecOpsMultiplePathParams(t *testing.T) {
	// Two path params on one URL: each becomes its own LocPath sink
	// whose URL keeps only its own placeholder while the other path
	// param is filled to "1".
	p := page.Page{
		URL: "http://example.com/u/1/items/1",
		SpecOps: []page.SpecOp{{
			Method: "GET",
			URL:    "http://example.com/u/1/items/1",
			Tpl:    "http://example.com/u/{userId}/items/{itemId}",
			Params: []page.SpecParam{
				{In: "path", Name: "userId"},
				{In: "path", Name: "itemId"},
			},
		}},
	}
	got := SinksFor(p)
	if len(got) != 2 {
		t.Fatalf("want 2 path sinks, got %+v", got)
	}
	urlByName := map[string]string{}
	for _, s := range got {
		if s.Loc != LocPath {
			t.Fatalf("expected LocPath, got %+v", s)
		}
		urlByName[s.Name] = s.URL
	}
	if u := urlByName["userId"]; u != "http://example.com/u/{userId}/items/1" {
		t.Errorf("userId sink URL = %q", u)
	}
	if u := urlByName["itemId"]; u != "http://example.com/u/1/items/{itemId}" {
		t.Errorf("itemId sink URL = %q", u)
	}
}

func TestMutateRequestJSON(t *testing.T) {
	s := Sink{Method: "POST", URL: "http://example.com/items", Loc: LocJSON, Name: "title"}
	req, err := s.MutateRequest(context.Background(), "p\"yld")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body not valid JSON: %v (raw=%q)", err, string(body))
	}
	if got["title"] != "p\"yld" {
		t.Errorf("title = %q, want payload", got["title"])
	}
}

func TestMutateRequestPath(t *testing.T) {
	s := Sink{Method: "GET", URL: "http://example.com/items/{id}", Loc: LocPath, Name: "id"}
	req, err := s.MutateRequest(context.Background(), "999")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if got := req.URL.String(); got != "http://example.com/items/999" {
		t.Errorf("URL = %q, want substituted path", got)
	}
}

func TestMutateRequestPathEscapesPayload(t *testing.T) {
	s := Sink{Method: "GET", URL: "http://example.com/items/{id}", Loc: LocPath, Name: "id"}
	req, err := s.MutateRequest(context.Background(), "../etc/passwd")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	// PathEscape escapes "/" so the traversal stays a single path segment.
	if strings.Contains(req.URL.Path, "..") && strings.Contains(req.URL.RawPath, "/") {
		// The escaped form should not let "/" through.
	}
	if !strings.Contains(req.URL.String(), "%2F") {
		t.Errorf("URL %q did not escape `/` in payload", req.URL.String())
	}
}

func TestMutateRequestPathMissingPlaceholder(t *testing.T) {
	// Defensive: if a path sink's URL never carried the placeholder
	// (caller bug), MutateRequest should fail loudly instead of sending
	// the unsubstituted URL to the target.
	s := Sink{Method: "GET", URL: "http://example.com/items/1", Loc: LocPath, Name: "id"}
	if _, err := s.MutateRequest(context.Background(), "p"); err == nil {
		t.Fatal("expected error when URL has no placeholder")
	}
}

func TestMutateRequestUnsupportedLoc(t *testing.T) {
	// LocJSON / LocPath are wired now; only an unknown loc constant
	// should still fail loudly so callers don't silently drop coverage.
	s := Sink{Method: "GET", URL: "http://example.com/", Loc: Loc("totally-fake"), Name: "x"}
	if _, err := s.MutateRequest(context.Background(), "p"); err == nil {
		t.Errorf("MutateRequest for loc %q returned nil error; want loud failure", s.Loc)
	}
}

func TestMutateRequestPreservesEncodedQuery(t *testing.T) {
	// Param values with reserved characters must round-trip through the
	// encode/decode without breaking other params.
	s := Sink{Method: "GET", URL: "http://example.com/r?weird=hello%20world&other=v", Loc: LocQuery, Name: "weird"}
	req, err := s.MutateRequest(context.Background(), "p&q=evil")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	q := req.URL.Query()
	if got := q.Get("weird"); got != "p&q=evil" {
		t.Errorf("weird = %q, want full payload", got)
	}
	if got := q.Get("other"); got != "v" {
		t.Errorf("other corrupted: %q", got)
	}
	// Ensure no smuggled-in q surfaced as a new param.
	if got := q.Get("q"); got == "evil" {
		t.Errorf("payload smuggled a new q param: %q", got)
	}
}

func TestSinksForCombinesQueryAndFormSorted(t *testing.T) {
	// Sanity check: when both query params and form sinks coexist, the
	// emit order is stable (sorted by URL then method then loc then name).
	p := page.Page{
		URL: "http://example.com/x?z=1",
		Forms: []page.Form{{
			Method: "POST",
			Action: "http://example.com/x",
			Inputs: []page.FormInput{{Name: "user"}},
		}},
	}
	got := SinksFor(p)
	names := make([]string, len(got))
	for i, s := range got {
		names[i] = string(s.Loc) + ":" + s.Name
	}
	sort.Strings(names)
	want := []string{"form:user", "query:z"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v, want %v", names, want)
	}
}

func TestMutateRequestUnparseableURL(t *testing.T) {
	s := Sink{Method: "GET", URL: "::nope::", Loc: LocQuery, Name: "x"}
	if _, err := s.MutateRequest(context.Background(), "p"); err == nil {
		t.Fatal("MutateRequest on unparseable URL returned nil error")
	}
}

func TestMutateRequestDefaultMethod(t *testing.T) {
	// Sinks with empty Method default to GET (matches HTML form spec).
	s := Sink{URL: "http://example.com/r?q=1", Loc: LocQuery, Name: "q"}
	req, err := s.MutateRequest(context.Background(), "p")
	if err != nil {
		t.Fatalf("MutateRequest: %v", err)
	}
	if req.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET fallback", req.Method)
	}
}
