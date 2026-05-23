package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
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
	stack, err := d.Detect(context.Background(), page.FromURL(srv.URL))
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

	stack, err := New(newTestClient(t)).Detect(context.Background(), page.FromURL(srv.URL))
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

	stack, err := New(newTestClient(t)).Detect(context.Background(), page.FromURL(srv.URL))
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

	stack, err := New(newTestClient(t)).Detect(context.Background(), page.FromURL(srv.URL))
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
		if _, err := d.Detect(context.Background(), page.FromURL(srv.URL+"/page")); err != nil {
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
		_, _ = d.Detect(context.Background(), page.FromURL(srv.URL+"/a"))
		_, _ = d.Detect(context.Background(), page.FromURL(srv.URL+"/b"))
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("OnDetect calls = %d, want 1", got)
	}
}

func TestDetectReturnsErrorOnUnreachableHost(t *testing.T) {
	c := httpclient.New(httpclient.Config{Timeout: 1 * time.Second, UserAgent: "test"})
	d := New(c)
	stack, err := d.Detect(context.Background(), page.FromURL("http://hyperz-fp-test-no-such-host.invalid"))
	if err == nil {
		t.Fatal("expected error from unreachable host")
	}
	if stack == nil {
		t.Fatal("Detect returned nil stack on error; want empty stack")
	}
}

func TestDetectFallbackProbeLiftsSPAEmptyHead(t *testing.T) {
	// SPA shell: empty <head>, no CMS/framework signal in headers or body.
	// /robots.txt exposes the wp-admin path; fallback probe should pick it up
	// and lift the CMS to wordpress even though the seed yielded nothing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /wp-admin/\n"))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head></head><body><div id="app"></div></body></html>`))
		}
	}))
	defer srv.Close()

	d := New(newTestClient(t), WithFallbackProbes("/robots.txt"))
	stack, err := d.Detect(context.Background(), page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.CMS != "wordpress" {
		t.Errorf("CMS = %q, want wordpress (fallback probe should have lifted it)", stack.CMS)
	}
	if stack.Language != "php" {
		t.Errorf("Language = %q, want php", stack.Language)
	}
}

func TestDetectFallbackProbeShortCircuitsOnSignal(t *testing.T) {
	// First probe yields wordpress; the second probe must not be requested.
	var probeHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			probeHits.Add(1)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Disallow: /wp-content/\n"))
		case "/wp-login.php":
			probeHits.Add(1)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<meta name="generator" content="WordPress 6.4">`))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head></head></html>`))
		}
	}))
	defer srv.Close()

	d := New(newTestClient(t), WithFallbackProbes("/robots.txt", "/wp-login.php"))
	if _, err := d.Detect(context.Background(), page.FromURL(srv.URL)); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got := probeHits.Load(); got != 1 {
		t.Errorf("probe hits = %d, want 1 (walk must stop after first signal)", got)
	}
}

func TestDetectFallbackProbeSkippedWhenSeedAlreadyKnowsCMS(t *testing.T) {
	// Seed already pins the CMS via meta-generator; the detector must not
	// burn a request on the fallback probe.
	var probeHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			probeHits.Add(1)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<meta name="generator" content="WordPress 6.4">`))
	}))
	defer srv.Close()

	d := New(newTestClient(t), WithFallbackProbes("/robots.txt"))
	if _, err := d.Detect(context.Background(), page.FromURL(srv.URL)); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got := probeHits.Load(); got != 0 {
		t.Errorf("probe hits = %d, want 0 (seed already populated CMS)", got)
	}
}

func TestDetectFallbackProbeDoesNotOverwriteSeedSignal(t *testing.T) {
	// Seed pins Server=nginx via header. A probe response carrying a different
	// Server value must not overwrite that - seed wins ties.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Server", "apache/2.4.49")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Disallow: /wp-admin/\n"))
		default:
			w.Header().Set("Server", "nginx/1.25.0")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head></head></html>`))
		}
	}))
	defer srv.Close()

	d := New(newTestClient(t), WithFallbackProbes("/robots.txt"))
	stack, err := d.Detect(context.Background(), page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.Server != "nginx" {
		t.Errorf("Server = %q, want nginx (seed must win over probe)", stack.Server)
	}
	if stack.CMS != "wordpress" {
		t.Errorf("CMS = %q, want wordpress (probe should still lift empty field)", stack.CMS)
	}
}

func TestDetectFallbackProbeSwallowsProbeErrors(t *testing.T) {
	// First probe path 404s, second yields the WordPress signal. The 404 must
	// not abort the walk; detection still completes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dead":
			http.NotFound(w, r)
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Disallow: /wp-admin/\n"))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><head></head></html>`))
		}
	}))
	defer srv.Close()

	d := New(newTestClient(t), WithFallbackProbes("/dead", "/robots.txt"))
	stack, err := d.Detect(context.Background(), page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.CMS != "wordpress" {
		t.Errorf("CMS = %q, want wordpress (404 probe should not abort walk)", stack.CMS)
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

func TestStackSummaryWithVersions(t *testing.T) {
	s := Stack{
		Server:   "nginx",
		Language: "php",
		CMS:      "wordpress",
		Versions: map[string]string{
			"server":   "1.25.0",
			"language": "8.2.0",
			// cms version unknown - should render as "cms=wordpress" with no slash.
		},
	}
	got := s.Summary()
	want := "server=nginx/1.25.0 language=php/8.2.0 cms=wordpress"
	if got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
}

func TestConfidence(t *testing.T) {
	// 3 of 6 categories populated â†’ 0.5
	s := &Stack{Server: "nginx", Language: "php", CMS: "wordpress"}
	if got := confidenceOf(s); got != 0.5 {
		t.Errorf("confidence = %v, want 0.5", got)
	}
}

func TestDetectExtractsVersionsFromHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49 (Unix)")
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stack, err := New(newTestClient(t)).Detect(context.Background(), page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got := stack.Versions["server"]; got != "2.4.49" {
		t.Errorf("Versions[server] = %q, want 2.4.49", got)
	}
	if got := stack.Versions["language"]; got != "8.2.0" {
		t.Errorf("Versions[language] = %q, want 8.2.0", got)
	}
	if got := stack.Versions["framework"]; got != "4.0.30319" {
		t.Errorf("Versions[framework] = %q, want 4.0.30319", got)
	}
}

func TestDetectExtractsVersionFromMetaGenerator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.2">
</head></html>`))
	}))
	defer srv.Close()

	stack, err := New(newTestClient(t)).Detect(context.Background(), page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.CMS != "wordpress" {
		t.Errorf("CMS = %q, want wordpress", stack.CMS)
	}
	if got := stack.Versions["cms"]; got != "6.4.2" {
		t.Errorf("Versions[cms] = %q, want 6.4.2", got)
	}
}

func TestDetectNoVersionWhenAbsent(t *testing.T) {
	// Server identifier without a version string, plus a meta-generator
	// without a version - both should set identifiers but leave Versions
	// empty for those slots.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<meta name="generator" content="WordPress">`))
	}))
	defer srv.Close()

	stack, err := New(newTestClient(t)).Detect(context.Background(), page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if stack.Server != "nginx" || stack.CMS != "wordpress" {
		t.Fatalf("identifiers not set: %+v", stack)
	}
	if _, ok := stack.Versions["server"]; ok {
		t.Errorf("Versions[server] present without version in header")
	}
	if _, ok := stack.Versions["cms"]; ok {
		t.Errorf("Versions[cms] present without version in meta-generator")
	}
}

func TestDetectIgnoresXRuntimeAsVersion(t *testing.T) {
	// X-Runtime is request runtime in seconds (Rails), not a software
	// version. Its dotted-decimal value must not be captured as a version.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Runtime", "0.012345")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	stack, err := New(newTestClient(t)).Detect(context.Background(), page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for k, v := range stack.Versions {
		t.Errorf("unexpected Versions[%s] = %q from X-Runtime", k, v)
	}
}

func TestCompareVersion(t *testing.T) {
	s := Stack{Versions: map[string]string{
		"server":   "2.4.49",
		"language": "8.2.0",
	}}

	tests := []struct {
		name    string
		field   string
		other   string
		wantCmp int
		wantOK  bool
	}{
		{"less than", "server", "2.4.50", -1, true},
		{"equal", "server", "2.4.49", 0, true},
		{"greater than", "server", "2.4.48", 1, true},
		{"shorter other pads zeros", "server", "2.4", 1, true},
		{"shorter have pads zeros", "language", "8.2.0.0", 0, true},
		{"case-insensitive field", "SERVER", "2.4.50", -1, true},
		{"loose suffix on stored", "server", "2.4.49", 0, true},
		{"unknown field", "framework", "1.0.0", 0, false},
		{"unknown field name", "nope", "1.0.0", 0, false},
		{"malformed other", "server", "not-a-version", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmp, ok := s.CompareVersion(tt.field, tt.other)
			if cmp != tt.wantCmp || ok != tt.wantOK {
				t.Errorf("CompareVersion(%q, %q) = (%d, %v), want (%d, %v)",
					tt.field, tt.other, cmp, ok, tt.wantCmp, tt.wantOK)
			}
		})
	}
}

func TestCompareVersionToleratesSuffix(t *testing.T) {
	// "2.4.49-ubuntu1" should still compare against "2.4.49" - the
	// non-numeric suffix on the last segment is dropped per parseVersion.
	s := Stack{Versions: map[string]string{"server": "2.4.49-ubuntu1"}}
	if cmp, ok := s.CompareVersion("server", "2.4.49"); cmp != 0 || !ok {
		t.Errorf("CompareVersion with suffix = (%d, %v), want (0, true)", cmp, ok)
	}
	if cmp, ok := s.CompareVersion("server", "2.4.50"); cmp != -1 || !ok {
		t.Errorf("CompareVersion suffix vs higher = (%d, %v), want (-1, true)", cmp, ok)
	}
}

func TestCompareVersionEmptyStack(t *testing.T) {
	// Nil Versions map must not panic.
	s := Stack{}
	if cmp, ok := s.CompareVersion("server", "1.0.0"); cmp != 0 || ok {
		t.Errorf("empty stack CompareVersion = (%d, %v), want (0, false)", cmp, ok)
	}
}
