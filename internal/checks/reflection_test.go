package checks

import (
	"net/http"
	"strings"
	"testing"
)

const refToken = "hpzc0123456789ab"

func TestFindReflectionsEmpty(t *testing.T) {
	if got := FindReflections([]byte("hello world"), nil, ""); got != nil {
		t.Errorf("empty token must return nil, got %+v", got)
	}
	if got := FindReflections(nil, nil, refToken); got != nil {
		t.Errorf("nil body must return nil, got %+v", got)
	}
	if got := FindReflections([]byte("nothing here"), nil, refToken); got != nil {
		t.Errorf("absent token must return nil, got %+v", got)
	}
}

func TestFindReflectionsHTMLText(t *testing.T) {
	body := []byte("<p>hello " + refToken + " world</p>")
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 {
		t.Fatalf("got %d hits, want 1: %+v", len(got), got)
	}
	if got[0].Context != CtxHTMLText {
		t.Errorf("context = %v, want CtxHTMLText", got[0].Context)
	}
	if got[0].Offset != 9 {
		t.Errorf("offset = %d, want 9", got[0].Offset)
	}
}

func TestFindReflectionsAttrDoubleQuoted(t *testing.T) {
	body := []byte(`<input value="` + refToken + `">`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxAttrDoubleQuoted {
		t.Fatalf("got %+v, want one CtxAttrDoubleQuoted", got)
	}
}

func TestFindReflectionsAttrSingleQuoted(t *testing.T) {
	body := []byte(`<input value='` + refToken + `'>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxAttrSingleQuoted {
		t.Fatalf("got %+v, want one CtxAttrSingleQuoted", got)
	}
}

func TestFindReflectionsAttrUnquoted(t *testing.T) {
	// Inside the tag, not in any quoted value. Could be an attribute
	// name or an unquoted value - both classify as CtxAttrUnquoted.
	body := []byte(`<input value=` + refToken + ` other=x>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxAttrUnquoted {
		t.Fatalf("got %+v, want one CtxAttrUnquoted", got)
	}
}

func TestFindReflectionsHTMLComment(t *testing.T) {
	body := []byte(`<!-- debug: ` + refToken + ` -->`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxHTMLComment {
		t.Fatalf("got %+v, want one CtxHTMLComment", got)
	}
}

func TestFindReflectionsAfterCommentBackToText(t *testing.T) {
	// Token after the comment must classify as text again - the state
	// machine has to transition out on `-->`.
	body := []byte(`<!-- hidden --><p>` + refToken + `</p>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxHTMLText {
		t.Fatalf("got %+v, want one CtxHTMLText after comment", got)
	}
}

func TestFindReflectionsScriptText(t *testing.T) {
	body := []byte(`<script>var x = ` + refToken + `;</script>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxScriptText {
		t.Fatalf("got %+v, want one CtxScriptText", got)
	}
}

func TestFindReflectionsScriptStringDouble(t *testing.T) {
	body := []byte(`<script>var x = "` + refToken + `";</script>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxScriptStringDouble {
		t.Fatalf("got %+v, want one CtxScriptStringDouble", got)
	}
}

func TestFindReflectionsScriptStringSingle(t *testing.T) {
	body := []byte(`<script>var x = '` + refToken + `';</script>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxScriptStringSingle {
		t.Fatalf("got %+v, want one CtxScriptStringSingle", got)
	}
}

func TestFindReflectionsScriptStringEscapeDoesNotTerminate(t *testing.T) {
	// An escaped quote inside a JS string must NOT terminate the string
	// state - otherwise a subsequent token inside the same string would
	// misclassify as CtxScriptText.
	body := []byte(`<script>var x = "esc \" still in str ` + refToken + `";</script>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxScriptStringDouble {
		t.Fatalf("got %+v, want CtxScriptStringDouble through escaped quote", got)
	}
}

func TestFindReflectionsAfterScriptBackToText(t *testing.T) {
	body := []byte(`<script>var x = 1;</script><p>` + refToken + `</p>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxHTMLText {
		t.Fatalf("got %+v, want CtxHTMLText after </script>", got)
	}
}

func TestFindReflectionsCaseInsensitiveScript(t *testing.T) {
	// HTML tag names are case-insensitive; the scanner has to recognize
	// `<SCRIPT>` and `</SCRIPT>` the same as the lowercase form.
	body := []byte(`<SCRIPT>var x = "` + refToken + `";</SCRIPT>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 1 || got[0].Context != CtxScriptStringDouble {
		t.Fatalf("got %+v, want CtxScriptStringDouble for <SCRIPT>", got)
	}
}

func TestFindReflectionsMultipleHits(t *testing.T) {
	body := []byte(
		`<p>` + refToken + `</p>` +
			`<input value="` + refToken + `">` +
			`<script>var x = '` + refToken + `';</script>`)
	got := FindReflections(body, nil, refToken)
	if len(got) != 3 {
		t.Fatalf("got %d hits, want 3: %+v", len(got), got)
	}
	wantCtx := []Context{CtxHTMLText, CtxAttrDoubleQuoted, CtxScriptStringSingle}
	for i, want := range wantCtx {
		if got[i].Context != want {
			t.Errorf("hit %d context = %v, want %v", i, got[i].Context, want)
		}
	}
	// Offsets must be strictly increasing - matches return in source order.
	for i := 1; i < len(got); i++ {
		if got[i].Offset <= got[i-1].Offset {
			t.Errorf("offsets not increasing: %d then %d", got[i-1].Offset, got[i].Offset)
		}
	}
}

func TestFindReflectionsHeader(t *testing.T) {
	headers := http.Header{
		"Location":         []string{"https://example.com/" + refToken},
		"X-Trace":          []string{"unrelated"},
		"X-Reflected-Twice": []string{refToken, "and " + refToken + " again"},
	}
	got := FindReflections(nil, headers, refToken)
	if len(got) < 2 {
		t.Fatalf("got %d header hits, want at least 2: %+v", len(got), got)
	}
	for _, r := range got {
		if r.Context != CtxHeaderValue {
			t.Errorf("got context %v, want CtxHeaderValue", r.Context)
		}
		if r.Offset != -1 {
			t.Errorf("header hit offset = %d, want -1", r.Offset)
		}
		if r.Header == "" {
			t.Errorf("header hit missing Header name: %+v", r)
		}
	}
}

func TestFindReflectionsBodyAndHeader(t *testing.T) {
	headers := http.Header{"X-Echo": []string{refToken}}
	body := []byte(`<p>` + refToken + `</p>`)
	got := FindReflections(body, headers, refToken)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2 (header + body): %+v", len(got), got)
	}
}

func TestHasReflection(t *testing.T) {
	if !HasReflection([]byte("abc"+refToken+"def"), nil, refToken) {
		t.Error("body hit not detected")
	}
	if !HasReflection(nil, http.Header{"X-Echo": []string{refToken}}, refToken) {
		t.Error("header hit not detected")
	}
	if HasReflection([]byte("nothing"), http.Header{"X-Echo": []string{"nope"}}, refToken) {
		t.Error("no token but HasReflection returned true")
	}
	if HasReflection([]byte("anything"), nil, "") {
		t.Error("empty token must always return false")
	}
}

func TestContextString(t *testing.T) {
	// Sanity check that every defined context has a non-default String
	// rendering - reports include this verbatim and an unknown render
	// would be confusing in a finding.
	cases := []Context{
		CtxHeaderValue, CtxHTMLText, CtxHTMLComment,
		CtxAttrDoubleQuoted, CtxAttrSingleQuoted, CtxAttrUnquoted,
		CtxScriptText, CtxScriptStringDouble, CtxScriptStringSingle,
	}
	for _, c := range cases {
		s := c.String()
		if s == "" || s == "none" {
			t.Errorf("Context(%d).String() = %q, want a non-empty name", c, s)
		}
		if strings.Contains(s, " ") {
			t.Errorf("Context(%d).String() = %q should be space-free for tagging", c, s)
		}
	}
	if CtxNone.String() != "none" {
		t.Errorf("CtxNone.String() = %q, want \"none\"", CtxNone.String())
	}
}
