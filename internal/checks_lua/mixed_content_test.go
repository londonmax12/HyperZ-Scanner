package checks_lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findMixedContent(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "mixed-content" {
			return c
		}
	}
	t.Fatal("mixed-content Lua check not found")
	return nil
}

// httpsTestPage builds a fully-populated Page for an HTTPS URL with
// the given body and Content-Type. The check looks at p.URL's scheme
// to decide whether to run, so we can use an arbitrary https:// URL
// rather than spin up a TLS test server for every scenario.
func httpsTestPage(body, ct string) page.Page {
	h := http.Header{}
	h.Set("Content-Type", ct)
	return page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: h,
		Body:    []byte(body),
		Fetched: true,
	}
}

func TestLuaMixedContentParityNoFindings(t *testing.T) {
	// HTTP page short-circuits.
	p := page.Page{
		URL:     "http://example.com/x",
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte(`<img src="http://x/a.png">`),
		Fetched: true,
	}
	fs, err := findMixedContent(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("HTTP page should produce no findings, got %d", len(fs))
	}
}

func TestLuaMixedContentParityMultipleTagsDedupePerURL(t *testing.T) {
	body := `<html><body>
<script src="http://cdn.example.com/app.js"></script>
<script src="http://cdn.example.com/app.js"></script>
<img src="http://img.example.com/a.png">
<link rel="stylesheet" href="http://cdn.example.com/style.css">
<form action="http://forms.example.com/submit"><input name="x"></form>
<a href="http://example.com/page">nav</a>
</body></html>`
	p := httpsTestPage(body, "text/html")

	goFs, err := (checks.MixedContent{}).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaFs, err := findMixedContent(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != len(luaFs) {
		t.Fatalf("count: go=%d lua=%d", len(goFs), len(luaFs))
	}
	goKeys := map[string]string{}
	for _, f := range goFs {
		goKeys[f.Title] = f.DedupeKey
	}
	for _, f := range luaFs {
		if goKeys[f.Title] != f.DedupeKey {
			t.Errorf("%q dedupe drift: go=%q lua=%q", f.Title, goKeys[f.Title], f.DedupeKey)
		}
	}
}

func TestLuaMixedContentParityCommentedTags(t *testing.T) {
	body := `<html><body>
<!-- <script src="http://evil.example.com/x.js"></script> -->
<p>hello</p>
</body></html>`
	p := httpsTestPage(body, "text/html")
	fs, err := findMixedContent(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("commented-out tags should produce no findings, got %d", len(fs))
	}
}

func TestLuaMixedContentParitySingleQuotedUppercase(t *testing.T) {
	body := `<html><body><img src='HTTP://images.example.com/x.png'></body></html>`
	p := httpsTestPage(body, "text/html")
	goFs, err := (checks.MixedContent{}).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaFs, err := findMixedContent(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != len(luaFs) {
		t.Fatalf("count drift: go=%d lua=%d", len(goFs), len(luaFs))
	}
}

func TestLuaMixedContentParityClassification(t *testing.T) {
	body := `<html><body>
<script src="http://cdn.example.com/app.js"></script>
<img src="http://img.example.com/banner.png">
</body></html>`
	p := httpsTestPage(body, "text/html")
	fs, err := findMixedContent(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	bySev := map[checks.Severity]string{}
	titles := []string{}
	for _, f := range fs {
		bySev[f.Severity] = f.Title
		titles = append(titles, f.Title)
	}
	sort.Strings(titles)
	if bySev[checks.SeverityHigh] == "" || !strings.Contains(bySev[checks.SeverityHigh], "<script>") {
		t.Errorf("expected high finding to be the script: titles=%v", titles)
	}
	if bySev[checks.SeverityLow] == "" || !strings.Contains(bySev[checks.SeverityLow], "<img>") {
		t.Errorf("expected low finding to be the img: titles=%v", titles)
	}
}

func TestLuaMixedContentSkippedOnNonHTML(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"href":"http://example.com/x.js"}`))
	}))
	defer srv.Close()
	// Caller-provided client must trust the test server's cert; easier
	// to short-circuit by handing the Page directly with a forged URL.
	p := httpsTestPage(`{"href":"http://example.com/x.js"}`, "application/json")
	fs, err := findMixedContent(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("non-HTML response should produce no findings, got %d", len(fs))
	}
}
