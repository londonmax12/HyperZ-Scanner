package checks

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestInsecureDeserializationName(t *testing.T) {
	if got := (InsecureDeserialization{}).Name(); got != "insecure-deserialization" {
		t.Fatalf("Name = %q, want insecure-deserialization", got)
	}
}

func TestInsecureDeserializationLevel(t *testing.T) {
	if got := (InsecureDeserialization{}).Level(); got != LevelDefault {
		t.Fatalf("Level = %v, want default", got)
	}
}

// deserialPageWithSetCookie builds a Page whose baseline snapshot already
// carries a Set-Cookie header, so the fingerprint arm sees the cookie
// without issuing any HTTP request. Tests that exercise the probe arm
// alongside the fingerprint arm pass the target URL the test server is
// listening on so probe requests reach a real handler.
func deserialPageWithSetCookie(targetURL, cookieName, cookieValue string) page.Page {
	return page.Page{
		URL:    targetURL,
		Status: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"text/html"},
			"Set-Cookie":   []string{cookieName + "=" + cookieValue + "; Path=/"},
		},
		Body:    []byte("<html><body>ok</body></html>"),
		Fetched: true,
	}
}

func TestInsecureDeserializationFingerprintJavaInSetCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	// Base64 of a real-shape Java serialized header: \xac\xed\x00\x05
	// (TC_HEADER, version 5) + TC_OBJECT (0x73) + TC_CLASSDESC (0x72) +
	// short class name. The fingerprint detector only requires the four
	// magic bytes after base64 decode.
	javaB64 := base64.StdEncoding.EncodeToString([]byte{
		0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x09, 'M', 'y', 'C', 'l', 'a', 's', 's',
	})
	p := deserialPageWithSetCookie(srv.URL, "JSESSIONID", javaB64)

	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Java ObjectInputStream") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected Java fingerprint finding, got: %+v", findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", hit.Severity)
	}
	if hit.CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", hit.CWE)
	}
	if !strings.Contains(hit.Title, "JSESSIONID") {
		t.Errorf("Title should mention the cookie name: %q", hit.Title)
	}
	if hit.DedupeKey == "" {
		t.Errorf("DedupeKey must be set")
	}
}

func TestInsecureDeserializationFingerprintPHPInQueryParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/")
	q := u.Query()
	q.Set("data", `O:8:"stdClass":1:{s:1:"x";i:1;}`)
	u.RawQuery = q.Encode()

	p := page.Page{
		URL:     u.String(),
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("ok"),
		Fetched: true,
	}
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "PHP unserialize") && strings.Contains(findings[i].Title, "query parameter") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected PHP query-param fingerprint finding, got: %+v", findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", hit.Severity)
	}
}

func TestInsecureDeserializationFingerprintDotNetInViewState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	raw := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00}
	vs := base64.StdEncoding.EncodeToString(raw)
	p := page.Page{
		URL:     srv.URL + "/",
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("ok"),
		Forms: []page.Form{{
			Method: "POST",
			Action: srv.URL + "/submit",
			Inputs: []page.FormInput{{Name: "__VIEWSTATE", Type: "hidden", Value: vs}},
		}},
		Fetched: true,
	}
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, ".NET BinaryFormatter") && strings.Contains(findings[i].Title, "form input") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected .NET form-input fingerprint finding, got: %+v", findings)
	}
	if !strings.Contains(hit.Title, "__VIEWSTATE") {
		t.Errorf("Title should mention __VIEWSTATE: %q", hit.Title)
	}
}

func TestInsecureDeserializationProbeDetectsPHPUnserializeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("payload")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.HasPrefix(v, `O:30:"HyperzNoSuchClassProbeXyz123"`) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Notice: unserialize(): Unable to find class 'HyperzNoSuchClassProbeXyz123' in /var/www/index.php on line 42")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer srv.Close()

	target := srv.URL + "/?payload=abc"
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Insecure deserialization (PHP unserialize") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected PHP probe finding, got: %+v", findings)
	}
	if hit.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want high", hit.Severity)
	}
	if hit.CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", hit.CWE)
	}
	if hit.Evidence == nil || hit.Evidence.Exchange == nil {
		t.Fatalf("Evidence/Exchange must be set: %+v", hit.Evidence)
	}
	if !strings.Contains(hit.Detail, "payload") {
		t.Errorf("Detail should reference parameter name: %q", hit.Detail)
	}
}

func TestInsecureDeserializationProbeDetectsPickleError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("d")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.HasPrefix(v, "gASV") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "_pickle.UnpicklingError: pickle data was truncated")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	target := srv.URL + "/?d=test"
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "Insecure deserialization (Python pickle") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected pickle probe finding, got: %+v", findings)
	}
}

func TestInsecureDeserializationProbeSuppressedByBaselinePattern(t *testing.T) {
	// Server returns the same generic PHP notice for every request,
	// including the canary baseline. The probe arm must subtract those
	// pre-existing patterns and emit no finding even though the response
	// matches an error pattern.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Notice: unserialize(): pre-existing notice present on every response")
	}))
	defer srv.Close()

	target := srv.URL + "/?d=test"
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, page.FromURL(target))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "Insecure deserialization (PHP") {
			t.Fatalf("baseline-present pattern should not produce a probe finding: %+v", f)
		}
	}
}

func TestInsecureDeserializationRespectsScope(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), sc, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings out of scope, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; out-of-scope check must not probe", got)
	}
}

func TestInsecureDeserializationBodyMarkerAggressive(t *testing.T) {
	p := page.Page{
		URL:     "https://example.test/",
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("<html><body>session=rO0ABXNyAA</body></html>"),
		Fetched: true,
	}
	ctx := WithLevel(context.Background(), LevelAggressive)
	findings, err := InsecureDeserialization{}.Run(ctx, newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var hit *Finding
	for i := range findings {
		if strings.Contains(findings[i].Title, "exposed in response body") {
			hit = &findings[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("expected body-fingerprint finding at aggressive, got: %+v", findings)
	}
	if hit.Severity != SeverityMedium {
		t.Errorf("Severity = %q, want medium (body fingerprint is leakage, not a proven sink)", hit.Severity)
	}
}

func TestInsecureDeserializationBodyMarkerSuppressedAtDefault(t *testing.T) {
	p := page.Page{
		URL:     "https://example.test/",
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html"}},
		Body:    []byte("<html><body>session=rO0ABXNyAA</body></html>"),
		Fetched: true,
	}
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "exposed in response body") {
			t.Fatalf("body-fingerprint must not fire at LevelDefault: %+v", f)
		}
	}
}

func TestInsecureDeserializationDedupeKeyStableAcrossRuns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	javaB64 := base64.StdEncoding.EncodeToString([]byte{0xac, 0xed, 0x00, 0x05, 's', 'r', 0x00, 0x0a})
	p := deserialPageWithSetCookie(srv.URL, "JSESSIONID", javaB64)

	run := func() string {
		fs, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, p)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		for _, f := range fs {
			if strings.Contains(f.Title, "Java ObjectInputStream") {
				return f.DedupeKey
			}
		}
		t.Fatalf("expected Java finding, got: %+v", fs)
		return ""
	}
	if a, b := run(), run(); a != b {
		t.Errorf("DedupeKey not stable: %q vs %q", a, b)
	}
}

func TestInsecureDeserializationIgnoresMalformedURL(t *testing.T) {
	findings, err := InsecureDeserialization{}.Run(context.Background(), newTestClient(t), nil, page.FromURL("not-a-url"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("malformed URL should produce 0 findings, got %+v", findings)
	}
}

func TestClassifyDeserial(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // format.name or "" for no match
	}{
		{
			name: "java-b64",
			in:   base64.StdEncoding.EncodeToString([]byte{0xac, 0xed, 0x00, 0x05, 's', 'r'}),
			want: "java",
		},
		{
			name: "dotnet-b64",
			in: base64.StdEncoding.EncodeToString([]byte{
				0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
			}),
			want: "dotnet",
		},
		{
			name: "pickle-p4-b64",
			in: base64.StdEncoding.EncodeToString([]byte{
				0x80, 0x04, 0x95, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			}),
			want: "pickle",
		},
		{
			name: "pickle-p2-b64",
			in:   base64.StdEncoding.EncodeToString([]byte{0x80, 0x02, '}', 'q'}),
			want: "pickle",
		},
		{
			name: "ruby-b64",
			in:   base64.StdEncoding.EncodeToString([]byte{0x04, 0x08, 'o', ':', 0x06, 'X'}),
			want: "ruby",
		},
		{
			name: "php-object",
			in:   `O:8:"stdClass":0:{}`,
			want: "php",
		},
		{
			name: "php-array",
			in:   `a:1:{i:0;i:1;}`,
			want: "php",
		},
		{
			name: "node-serialize-marker",
			in:   `{"r":"_$$ND_FUNC$$_function(){return 1}()"}`,
			want: "node-serialize",
		},
		{
			name: "yaml-python-object",
			in:   "!!python/object/apply:os.system",
			want: "yaml",
		},
		{
			name: "yaml-ruby-object",
			in:   "!!ruby/object:Gem::Installer",
			want: "yaml",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
		{
			name: "plain-text",
			in:   "this is just regular page content nothing serialized",
			want: "",
		},
		{
			name: "plain-json",
			in:   `{"foo":"bar"}`,
			want: "",
		},
		{
			name: "ruby-too-short",
			in:   base64.StdEncoding.EncodeToString([]byte{0x04, 0x08}),
			want: "",
		},
		{
			name: "ruby-bad-tag",
			in:   base64.StdEncoding.EncodeToString([]byte{0x04, 0x08, 0x99, 0x00, 0x00, 0x00}),
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := classifyDeserial(tc.in)
			got := ""
			if fp != nil {
				got = fp.name
			}
			if got != tc.want {
				t.Errorf("classifyDeserial(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBodyDeserialMarker(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // substring expected in returned marker, "" for no match
	}{
		{"empty", "", ""},
		{"java-b64", "session=rO0ABxyz", "Java"},
		{"dotnet-b64", "viewstate=AAEAAAD/////AQAA", ".NET"},
		{"node-serialize", `funcs:["_$$ND_FUNC$$_function..."]`, "node-serialize"},
		{"yaml-python", "value: !!python/object/apply:os.system", "python/object"},
		{"yaml-ruby", "config:\n  !!ruby/object:Gem::Installer\n  name: foo", "ruby/object"},
		{"plain-html", "<html><body>nothing serialized here</body></html>", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bodyDeserialMarker([]byte(tc.body))
			if tc.want == "" {
				if got != "" {
					t.Errorf("bodyDeserialMarker(%q) = %q, want \"\"", tc.body, got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("bodyDeserialMarker(%q) = %q, want substring %q", tc.body, got, tc.want)
			}
		})
	}
}
