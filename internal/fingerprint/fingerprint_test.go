package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonball/hyperz/internal/httpclient"
)

func newTestClient(t *testing.T) *httpclient.Client {
	t.Helper()
	return httpclient.New(httpclient.Config{
		Timeout:   5 * time.Second,
		UserAgent: "test",
	})
}

func TestDetectFromServerAndPoweredBy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New(newTestClient(t))
	stack, err := d.Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.Server != "nginx" {
		t.Errorf("Server = %q, want nginx", stack.Server)
	}
	if stack.Language != "php" {
		t.Errorf("Language = %q, want php", stack.Language)
	}
	if stack.Confidence <= 0 {
		t.Errorf("Confidence = %v, want > 0", stack.Confidence)
	}
}

func TestDetectFromCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "laravel_session", Value: "x"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stack, err := New(newTestClient(t)).Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.Framework != "laravel" {
		t.Errorf("Framework = %q, want laravel", stack.Framework)
	}
	if stack.Language != "php" {
		t.Errorf("Language = %q, want php", stack.Language)
	}
}

func TestDetectFromHTMLBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4">
</head><body><img src="/wp-content/uploads/x.png"></body></html>`))
	}))
	defer srv.Close()

	stack, err := New(newTestClient(t)).Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.CMS != "wordpress" {
		t.Errorf("CMS = %q, want wordpress", stack.CMS)
	}
	if stack.Language != "php" {
		t.Errorf("Language = %q, want php", stack.Language)
	}
}

func TestDetectCDNAndWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-Ray", "abc123-LHR")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stack, err := New(newTestClient(t)).Detect(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.CDN != "cloudflare" {
		t.Errorf("CDN = %q, want cloudflare", stack.CDN)
	}
	if stack.WAF != "cloudflare" {
		t.Errorf("WAF = %q, want cloudflare", stack.WAF)
	}
}

func TestDetectCachesByHost(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New(newTestClient(t))
	for i := 0; i < 5; i++ {
		if _, err := d.Detect(context.Background(), srv.URL+"/page"); err != nil {
			t.Fatalf("Detect: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server hits = %d, want 1 (cache should suppress repeat detection)", got)
	}
}

func TestDetectOnDetectFiresOncePerHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var calls atomic.Int64
	d := New(newTestClient(t), WithOnDetect(func(host string, s *Stack) {
		calls.Add(1)
	}))
	for i := 0; i < 3; i++ {
		_, _ = d.Detect(context.Background(), srv.URL+"/a")
		_, _ = d.Detect(context.Background(), srv.URL+"/b")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("OnDetect calls = %d, want 1", got)
	}
}

func TestDetectReturnsErrorOnUnreachableHost(t *testing.T) {
	c := httpclient.New(httpclient.Config{Timeout: 1 * time.Second, UserAgent: "test"})
	d := New(c)
	stack, err := d.Detect(context.Background(), "http://hyperz-fp-test-no-such-host.invalid")
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
	if stack == nil {
		t.Fatal("Detect returned nil stack on error; want empty stack")
	}
}

func TestStackMatchesAndHas(t *testing.T) {
	s := Stack{Server: "nginx", Language: "php", CMS: "wordpress"}
	if !s.Matches("wordpress") {
		t.Errorf("Matches(wordpress) = false, want true")
	}
	if !s.Matches("drupal", "wordpress") {
		t.Errorf("Matches(drupal, wordpress) = false, want true")
	}
	if s.Matches("drupal", "joomla") {
		t.Errorf("Matches(drupal, joomla) = true, want false")
	}
	// Empty values must not match the zero-value Framework/CDN/WAF fields.
	if s.Matches("") {
		t.Errorf("Matches(empty) = true; empty values must not match unpopulated fields")
	}
	if !s.Has("language", "php", "ruby") {
		t.Errorf("Has(language, php, ruby) = false, want true")
	}
	if s.Has("framework", "rails") {
		t.Errorf("Has(framework, rails) = true; framework is empty")
	}
	if s.Has("nope", "anything") {
		t.Errorf("Has on unknown field = true, want false")
	}
}

func TestStackSummary(t *testing.T) {
	if got := (Stack{}).Summary(); got != "unknown" {
		t.Errorf("empty Summary = %q, want unknown", got)
	}
	got := Stack{Server: "nginx", Language: "php", CMS: "wordpress"}.Summary()
	want := "server=nginx language=php cms=wordpress"
	if got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
}

func TestConfidence(t *testing.T) {
	// 3 of 6 categories populated → 0.5
	s := &Stack{Server: "nginx", Language: "php", CMS: "wordpress"}
	if got := confidenceOf(s); got != 0.5 {
		t.Errorf("confidence = %v, want 0.5", got)
	}
}
