package crawler

import (
	"net/url"
	"reflect"
	"sort"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s, err)
	}
	return u
}

func TestExtractLinksResolvesRelative(t *testing.T) {
	base := mustParseURL(t, "http://example.com/page")
	body := []byte(`
		<a href="/abs">x</a>
		<a href="rel">y</a>
		<a href="http://other.example/full">z</a>
		<img src="/img.png">
	`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{
		"http://example.com/abs",
		"http://example.com/img.png",
		"http://example.com/rel",
		"http://other.example/full",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestExtractLinksDropsNonHTTPSchemes(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<a href="mailto:a@b">m</a>
		<a href="javascript:void(0)">j</a>
		<a href="ftp://x/y">f</a>
		<a href="http://ok">o</a>
	`)
	got := extractLinks(base, body)
	if len(got) != 1 || got[0] != "http://ok" {
		t.Fatalf("got %v, want [http://ok]", got)
	}
}

func TestExtractLinksStripsFragmentAndDedupes(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<a href="/p#one">1</a>
		<a href="/p#two">2</a>
		<a href="/p">3</a>
	`)
	got := extractLinks(base, body)
	if len(got) != 1 || got[0] != "http://example.com/p" {
		t.Fatalf("got %v, want [http://example.com/p]", got)
	}
}

func TestExtractLinksCaseInsensitiveAttrs(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`<A HREF='/x'>x</A><SCRIPT SRC="/y.js"></SCRIPT>`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{"http://example.com/x", "http://example.com/y.js"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractLinksEmptyBody(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	if got := extractLinks(base, nil); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestExtractLinksCoversFullTagSet(t *testing.T) {
	// The regex predecessor only knew href/src on any element. The tokenizer
	// rewrite is supposed to cover every element that actually carries a
	// navigable URL - this pins the list so a regression in the switch
	// statement above shows up loudly.
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<link rel="stylesheet" href="/s.css">
		<area href="/area">
		<iframe src="/frame"></iframe>
		<frame src="/old-frame">
		<script src="/s.js"></script>
		<audio src="/a.mp3"></audio>
		<video src="/v.mp4"></video>
		<source src="/s.webm">
		<embed src="/e.swf">
		<track src="/t.vtt">
	`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{
		"http://example.com/a.mp3",
		"http://example.com/area",
		"http://example.com/e.swf",
		"http://example.com/frame",
		"http://example.com/old-frame",
		"http://example.com/s.css",
		"http://example.com/s.js",
		"http://example.com/s.webm",
		"http://example.com/t.vtt",
		"http://example.com/v.mp4",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestExtractLinksHandlesSrcset(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<img srcset="/img-1x.png 1x, /img-2x.png 2x, /img-full.png 800w">
		<source srcset="/srcset-source.png">
	`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{
		"http://example.com/img-1x.png",
		"http://example.com/img-2x.png",
		"http://example.com/img-full.png",
		"http://example.com/srcset-source.png",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestExtractLinksHandlesMetaRefresh(t *testing.T) {
	base := mustParseURL(t, "http://example.com/page")
	body := []byte(`
		<meta http-equiv="refresh" content="0; url=/refresh-target">
		<meta HTTP-EQUIV="REFRESH" content='5;URL="https://other.example/q"'>
		<meta http-equiv="refresh" content="10">
	`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{
		"http://example.com/refresh-target",
		"https://other.example/q",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestExtractLinksHonorsBaseHref(t *testing.T) {
	// <base href="..."> sets the document base for the whole page, including
	// elements that appear before it in source - matching browsers and the
	// HTML spec. A pre-pass locates the tag before the main extraction walk.
	base := mustParseURL(t, "http://example.com/dir/")
	body := []byte(`
		<a href="before">b</a>
		<base href="http://cdn.example/static/">
		<a href="after">a</a>
	`)
	got := extractLinks(base, body)
	sort.Strings(got)
	want := []string{
		"http://cdn.example/static/after",
		"http://cdn.example/static/before",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestExtractLinksFirstBaseHrefWins(t *testing.T) {
	// HTML spec: only the first <base> with a usable href affects the
	// document base. Tags without href, or with a non-http(s) scheme, are
	// skipped in favor of the next candidate.
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<base target="_blank">
		<base href="javascript:void(0)">
		<base href="http://first.example/p/">
		<base href="http://second.example/q/">
		<a href="x">x</a>
	`)
	got := extractLinks(base, body)
	want := []string{"http://first.example/p/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestExtractFormsHonorsBaseHrefBeforeForm(t *testing.T) {
	// Form actions resolve against the document base too. A form that
	// appears before <base> still picks up the override, so active checks
	// don't end up fuzzing the original host by mistake.
	base := mustParseURL(t, "http://example.com/dir/")
	body := []byte(`
		<form action="submit" method="post"><input name="a"></form>
		<base href="http://api.example/v1/">
	`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %d forms, want 1", len(got))
	}
	if got[0].Action != "http://api.example/v1/submit" {
		t.Errorf("Action = %q, want http://api.example/v1/submit", got[0].Action)
	}
}

func TestExtractFormsBasicGetForm(t *testing.T) {
	base := mustParseURL(t, "http://example.com/page")
	body := []byte(`
		<form action="/search" method="get">
			<input type="text" name="q" value="default">
			<input type="hidden" name="csrf" value="abc123">
			<button name="submit" type="submit" value="go">Go</button>
		</form>
	`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %d forms, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.Method != "GET" {
		t.Errorf("Method = %q, want GET", f.Method)
	}
	if f.Action != "http://example.com/search" {
		t.Errorf("Action = %q, want http://example.com/search", f.Action)
	}
	want := []page.FormInput{
		{Name: "q", Type: "text", Value: "default"},
		{Name: "csrf", Type: "hidden", Value: "abc123"},
		{Name: "submit", Type: "submit", Value: "go"},
	}
	if !reflect.DeepEqual(f.Inputs, want) {
		t.Errorf("Inputs = %+v\nwant %+v", f.Inputs, want)
	}
}

func TestExtractFormsDefaultMethodIsGet(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`<form action="/x"><input name="a"></form>`)
	got := extractForms(base, body)
	if len(got) != 1 || got[0].Method != "GET" {
		t.Fatalf("got %+v, want one form with Method=GET", got)
	}
}

func TestExtractFormsEmptyActionPostsToSelf(t *testing.T) {
	base := mustParseURL(t, "http://example.com/login?next=/dashboard")
	body := []byte(`<form method="POST"><input name="user"></form>`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %+v, want one form", got)
	}
	want := "http://example.com/login?next=/dashboard"
	if got[0].Action != want {
		t.Errorf("Action = %q, want %q", got[0].Action, want)
	}
}

func TestExtractFormsUnknownMethodFallsBackToGet(t *testing.T) {
	// HTML5 form-level method is GET or POST. Anything else (DELETE, etc.)
	// browsers treat as GET.
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`<form action="/x" method="delete"></form>`)
	got := extractForms(base, body)
	if len(got) != 1 || got[0].Method != "GET" {
		t.Fatalf("got %+v, want Method=GET fallback", got)
	}
}

func TestExtractFormsTextareaAndSelectInputs(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<form action="/submit" method="post">
			<textarea name="comment">hello world</textarea>
			<select name="country"><option>US</option></select>
		</form>
	`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %d forms, want 1", len(got))
	}
	want := []page.FormInput{
		{Name: "country", Type: "select", Value: "", Options: []string{"US"}},
		{Name: "comment", Type: "textarea", Value: "hello world"},
	}
	// The walker emits inputs in document order: <textarea>'s close
	// triggers its FormInput, but <select>'s FormInput is appended at
	// the start tag. Compare as sets to avoid pinning that detail.
	gotSet := map[string]page.FormInput{}
	for _, in := range got[0].Inputs {
		gotSet[in.Name] = in
	}
	wantSet := map[string]page.FormInput{}
	for _, in := range want {
		wantSet[in.Name] = in
	}
	if !reflect.DeepEqual(gotSet, wantSet) {
		t.Errorf("Inputs = %+v\nwant %+v", gotSet, wantSet)
	}
}

func TestExtractFormsSelectOptions(t *testing.T) {
	// <select> options - both value="..." and text-only - are captured in
	// document order. The pollute-gated crawler uses Options to fan one
	// POST out per choice; if we drop a value here the walk skips that
	// destination on every site that uses select-driven navigation.
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<form action="/portal" method="post">
			<select name="bug">
				<option value="1">First</option>
				<option value="2">Second</option>
				<option>Third</option>
				<option value="">Empty</option>
			</select>
		</form>
	`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %d forms, want 1", len(got))
	}
	var sel page.FormInput
	for _, in := range got[0].Inputs {
		if in.Type == "select" {
			sel = in
		}
	}
	want := []string{"1", "2", "Third", ""}
	if !reflect.DeepEqual(sel.Options, want) {
		t.Errorf("Options = %v, want %v", sel.Options, want)
	}
}

func TestExtractFormsSelectResetsBetweenSelects(t *testing.T) {
	// Two selects in one form must not bleed options into each other,
	// and an unnamed select (dropped at the start tag) must not let its
	// options leak onto the previous named select.
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<form action="/x" method="post">
			<select name="a">
				<option value="a1">a1</option>
			</select>
			<select>
				<option value="ghost">ghost</option>
			</select>
			<select name="b">
				<option value="b1">b1</option>
			</select>
		</form>
	`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %d forms, want 1", len(got))
	}
	bySel := map[string][]string{}
	for _, in := range got[0].Inputs {
		if in.Type == "select" {
			bySel[in.Name] = in.Options
		}
	}
	if !reflect.DeepEqual(bySel["a"], []string{"a1"}) {
		t.Errorf("select a Options = %v, want [a1]", bySel["a"])
	}
	if !reflect.DeepEqual(bySel["b"], []string{"b1"}) {
		t.Errorf("select b Options = %v, want [b1]", bySel["b"])
	}
}

func TestExtractFormsSkipsUnnamedInputs(t *testing.T) {
	// Inputs without a name attribute are never submitted by browsers, so
	// fuzzing them is wasted effort. The extractor drops them up front.
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<form action="/x" method="post">
			<input type="text" value="anon">
			<input type="text" name="real" value="v">
		</form>
	`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %d forms, want 1", len(got))
	}
	if len(got[0].Inputs) != 1 || got[0].Inputs[0].Name != "real" {
		t.Fatalf("Inputs = %+v, want only [real]", got[0].Inputs)
	}
}

func TestExtractFormsAbsoluteAction(t *testing.T) {
	base := mustParseURL(t, "http://example.com/page")
	body := []byte(`<form action="https://api.example.com/v1/users" method="post"><input name="u"></form>`)
	got := extractForms(base, body)
	if len(got) != 1 {
		t.Fatalf("got %+v, want 1 form", got)
	}
	if got[0].Action != "https://api.example.com/v1/users" {
		t.Errorf("Action = %q, want absolute URL preserved", got[0].Action)
	}
}

func TestExtractFormsMultipleForms(t *testing.T) {
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`
		<form action="/a" method="get"><input name="x"></form>
		<form action="/b" method="post"><input name="y"></form>
	`)
	got := extractForms(base, body)
	if len(got) != 2 {
		t.Fatalf("got %d forms, want 2", len(got))
	}
	if got[0].Action != "http://example.com/a" || got[0].Method != "GET" {
		t.Errorf("form 0 = %+v", got[0])
	}
	if got[1].Action != "http://example.com/b" || got[1].Method != "POST" {
		t.Errorf("form 1 = %+v", got[1])
	}
}

func TestExtractFormsHandlesUnclosedForm(t *testing.T) {
	// Browsers tolerate missing </form>. The extractor should too - real
	// templates ship malformed HTML often enough that dropping unclosed
	// forms would lose findings.
	base := mustParseURL(t, "http://example.com/")
	body := []byte(`<form action="/x" method="post"><input name="a" value="1">`)
	got := extractForms(base, body)
	if len(got) != 1 || got[0].Action != "http://example.com/x" {
		t.Fatalf("got %+v, want one form with action /x", got)
	}
	if len(got[0].Inputs) != 1 || got[0].Inputs[0].Name != "a" {
		t.Errorf("Inputs = %+v, want [a]", got[0].Inputs)
	}
}
