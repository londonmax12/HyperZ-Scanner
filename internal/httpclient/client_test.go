package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestHostOf(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"http://a.example:81/path", "a.example:81", false},
		{"https://b.example/", "b.example", false},
		{"://bad", "", true},
	}
	for _, c := range cases {
		got, err := hostOf(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}
