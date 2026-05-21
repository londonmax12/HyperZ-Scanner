package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientGetSetsUserAgent(t *testing.T) {
	var gotUA atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA.Store(r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "hyperz-test/1"})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := gotUA.Load(); got != "hyperz-test/1" {
		t.Fatalf("UA = %v, want hyperz-test/1", got)
	}
}

func TestClientGetHonorsContext(t *testing.T) {
	// Server hangs forever; ctx cancellation must abort the request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before issuing
	_, err := c.Get(ctx, srv.URL)
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestClientGetUsesLimiter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 2 rps, burst 1 → second request must wait ~500ms.
	lim := NewHostLimiter(2, 1)
	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test", Limiter: lim})

	start := time.Now()
	for i := 0; i < 2; i++ {
		resp, err := c.Get(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Fatalf("two requests at 2rps/burst1 took %v, expected ≥300ms", elapsed)
	}
}

func TestClientGetReturnsErrorOnBadURL(t *testing.T) {
	c := New(Config{Timeout: 1 * time.Second, UserAgent: "test"})
	_, err := c.Get(context.Background(), "://bad-url")
	if err == nil {
		t.Fatal("expected error from malformed URL")
	}
}

func TestClientUsesProxyFunc(t *testing.T) {
	var proxied atomic.Int64
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxySrv.Close()
	pu, _ := url.Parse(proxySrv.URL)

	c := New(Config{
		Timeout:   5 * time.Second,
		UserAgent: "test",
		Proxy:     func(*http.Request) (*url.URL, error) { return pu, nil },
	})
	resp, err := c.Get(context.Background(), "http://example.invalid/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if proxied.Load() != 1 {
		t.Fatalf("proxy hits = %d, want 1", proxied.Load())
	}
}

func TestClientCustomTransportOverrides(t *testing.T) {
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 418,
			Body:       io.NopCloser(nil),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	c := New(Config{Timeout: time.Second, UserAgent: "t", Transport: rt})
	resp, err := c.Get(context.Background(), "http://anywhere/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 418 {
		t.Fatalf("status = %d, want 418", resp.StatusCode)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// recordingSleep stubs Client.sleepFn so tests can assert on requested
// sleep durations without actually waiting.
type recordingSleep struct {
	waits []time.Duration
}

func (r *recordingSleep) fn(_ context.Context, d time.Duration) error {
	r.waits = append(r.waits, d)
	return nil
}

func TestClientDoRetriesOn429WithRetryAfterSeconds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test", MaxRetries: 2})
	sleeps := &recordingSleep{}
	c.sleepFn = sleeps.fn

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}
	if hits.Load() != 2 {
		t.Fatalf("server hits = %d, want 2 (1 retry)", hits.Load())
	}
	if len(sleeps.waits) != 1 || sleeps.waits[0] != 2*time.Second {
		t.Fatalf("sleeps = %v, want [2s]", sleeps.waits)
	}
}

func TestClientDoRetriesOn503WithRetryAfterDate(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			// HTTP-date format, 5 seconds in the future from the test's
			// frozen "now" below.
			w.Header().Set("Retry-After", "Mon, 02 Jan 2006 15:04:10 GMT")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test", MaxRetries: 1})
	now, _ := time.Parse(http.TimeFormat, "Mon, 02 Jan 2006 15:04:05 GMT")
	c.nowFn = func() time.Time { return now }
	sleeps := &recordingSleep{}
	c.sleepFn = sleeps.fn

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, want 200", resp.StatusCode)
	}
	if len(sleeps.waits) != 1 || sleeps.waits[0] != 5*time.Second {
		t.Fatalf("sleeps = %v, want [5s] parsed from HTTP-date", sleeps.waits)
	}
}

func TestClientDoCapsRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3600") // server asks for 1h
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New(Config{
		Timeout: 5 * time.Second, UserAgent: "test",
		MaxRetries: 1, MaxRetryWait: 250 * time.Millisecond,
	})
	sleeps := &recordingSleep{}
	c.sleepFn = sleeps.fn

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if len(sleeps.waits) != 1 || sleeps.waits[0] != 250*time.Millisecond {
		t.Fatalf("sleeps = %v, want [250ms] (capped)", sleeps.waits)
	}
}

func TestClientDoExponentialBackoffWhenNoRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New(Config{
		Timeout: 5 * time.Second, UserAgent: "test",
		MaxRetries: 3, MaxRetryWait: time.Hour, // large cap so backoff isn't clamped
	})
	sleeps := &recordingSleep{}
	c.sleepFn = sleeps.fn

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	if len(sleeps.waits) != len(want) {
		t.Fatalf("sleeps = %v, want %v", sleeps.waits, want)
	}
	for i := range want {
		if sleeps.waits[i] != want[i] {
			t.Fatalf("sleep[%d] = %v, want %v", i, sleeps.waits[i], want[i])
		}
	}
}

func TestClientDoGivesUpAfterMaxRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test", MaxRetries: 2})
	c.sleepFn = (&recordingSleep{}).fn

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("final status = %d, want 429", resp.StatusCode)
	}
	if hits.Load() != 3 { // initial + 2 retries
		t.Fatalf("server hits = %d, want 3", hits.Load())
	}
}

func TestClientDoDoesNotRetryNonIdempotent(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test", MaxRetries: 3})
	c.sleepFn = (&recordingSleep{}).fn

	req, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader("x=1"))
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("POST hits = %d, want 1 (no retry for non-idempotent)", hits.Load())
	}
}

func TestClientDoRetryPenalizesLimiter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	lim := NewHostLimiter(10, 1)
	c := New(Config{
		Timeout: 5 * time.Second, UserAgent: "test",
		Limiter: lim, MaxRetries: 2,
	})
	c.sleepFn = (&recordingSleep{}).fn

	u, _ := url.Parse(srv.URL)
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	// Three 429 responses → three penalties → 10 → 5 → 2.5 → 1.25.
	if got := lim.Limit(u.Host); got != 1.25 {
		t.Fatalf("post-retry limiter rate = %v, want 1.25", got)
	}
}

func TestClientDoNoRetryWhenMaxRetriesZero(t *testing.T) {
	// Sanity: default config preserves original single-shot behavior, so a
	// 429 surfaces unchanged and the limiter is still penalized once.
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	lim := NewHostLimiter(10, 1)
	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test", Limiter: lim})

	u, _ := url.Parse(srv.URL)
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d, want 1 (no retry)", hits.Load())
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	if got := lim.Limit(u.Host); got != 5 {
		t.Fatalf("limiter rate after 1 429 = %v, want 5 (penalized once)", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now, _ := time.Parse(http.TimeFormat, "Mon, 02 Jan 2006 15:04:05 GMT")
	cases := []struct {
		in      string
		want    time.Duration
		wantOK  bool
	}{
		{"", 0, false},
		{"abc", 0, false},
		{"7", 7 * time.Second, true},
		{"  3  ", 3 * time.Second, true},
		{"Mon, 02 Jan 2006 15:04:15 GMT", 10 * time.Second, true},
	}
	for _, tc := range cases {
		got, ok := parseRetryAfter(tc.in, now)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("parseRetryAfter(%q) = (%v, %v), want (%v, %v)",
				tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestClientDoPostWithCustomHeadersAndBody(t *testing.T) {
	var (
		gotMethod, gotCT, gotXReq, gotUA string
		gotBody                          []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotXReq = r.Header.Get("X-Requested-With")
		gotUA = r.Header.Get("User-Agent")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "default-ua"})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/login", strings.NewReader("user=a&pass=b"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotXReq != "XMLHttpRequest" {
		t.Errorf("X-Requested-With = %q", gotXReq)
	}
	if gotUA != "default-ua" {
		t.Errorf("User-Agent = %q, want default-ua to fill when caller did not set it", gotUA)
	}
	if string(gotBody) != "user=a&pass=b" {
		t.Errorf("body = %q", string(gotBody))
	}
}

func TestClientDoRespectsCallerUserAgent(t *testing.T) {
	var gotUA atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA.Store(r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "default-ua"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "caller-ua")
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if got := gotUA.Load(); got != "caller-ua" {
		t.Fatalf("UA = %v, want caller-ua (caller's header must win)", got)
	}
}

func TestClientAppliesBasicAuth(t *testing.T) {
	var gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{
		Timeout:   5 * time.Second,
		UserAgent: "t",
		BasicAuth: &BasicAuth{Username: "alice", Password: "s3cret"},
	})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	got, _ := gotAuth.Load().(string)
	// "alice:s3cret" base64 → YWxpY2U6czNjcmV0
	if got != "Basic YWxpY2U6czNjcmV0" {
		t.Fatalf("Authorization = %q, want Basic YWxpY2U6czNjcmV0", got)
	}
}

func TestClientBasicAuthDoesNotOverrideExistingAuthorization(t *testing.T) {
	var gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{
		Timeout:   5 * time.Second,
		UserAgent: "t",
		BasicAuth: &BasicAuth{Username: "alice", Password: "x"},
	})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer caller-token")
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if got := gotAuth.Load(); got != "Bearer caller-token" {
		t.Fatalf("Authorization = %v, want caller's Bearer to win", got)
	}
}

func TestClientAppliesBearerToken(t *testing.T) {
	var gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{
		Timeout:     5 * time.Second,
		UserAgent:   "t",
		BearerToken: "abc.def.ghi",
	})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	if got := gotAuth.Load(); got != "Bearer abc.def.ghi" {
		t.Fatalf("Authorization = %v, want Bearer abc.def.ghi", got)
	}
}

func TestClientAppliesExtraHeaders(t *testing.T) {
	var gotKey, gotTrace atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("X-API-Key"))
		gotTrace.Store(r.Header.Get("X-Trace"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := http.Header{}
	h.Set("X-API-Key", "k-1")
	h.Set("X-Trace", "default-trace")
	c := New(Config{Timeout: 5 * time.Second, UserAgent: "t", ExtraHeaders: h})

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("X-Trace", "caller-trace") // caller wins
	resp, err := c.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if got := gotKey.Load(); got != "k-1" {
		t.Fatalf("X-API-Key = %v, want k-1", got)
	}
	if got := gotTrace.Load(); got != "caller-trace" {
		t.Fatalf("X-Trace = %v, want caller-trace (caller header wins)", got)
	}
}

func TestClientUsesCookieJar(t *testing.T) {
	var hits atomic.Int32
	var sawCookie atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		c, err := r.Cookie("sid")
		if err == nil {
			sawCookie.Store(c.Value)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	c := New(Config{Timeout: 5 * time.Second, UserAgent: "t", Jar: jar})

	for i := 0; i < 2; i++ {
		resp, err := c.Get(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		resp.Body.Close()
	}
	if got := sawCookie.Load(); got != "abc" {
		t.Fatalf("second request saw sid = %v, want abc (jar must replay Set-Cookie)", got)
	}
	if c.Jar() != jar {
		t.Fatal("Jar() did not return the configured jar")
	}
}

func TestClientDoHonorsCtxOverRequestCtx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := New(Config{Timeout: 5 * time.Second, UserAgent: "test"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil) // background ctx
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Do(ctx, req); err == nil {
		t.Fatal("expected error from canceled ctx passed to Do")
	}
}
