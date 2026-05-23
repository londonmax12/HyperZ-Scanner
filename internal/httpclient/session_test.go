package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
)

// stubReq returns a minimal *http.Request with a context attached so the
// sentinel's probe can receive it.
func stubReq() *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.invalid/", nil)
	return req
}

func TestSessionSentinelProbesOnFirstRequest(t *testing.T) {
	var probes atomic.Int32
	probe := func(ctx context.Context) (int, []byte, error) {
		probes.Add(1)
		return http.StatusOK, []byte("ok"), nil
	}
	s := NewSessionSentinel(10, probe, nil)
	if err := s.Before(stubReq()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probes after first call = %d, want 1", got)
	}
}

func TestSessionSentinelProbesEveryN(t *testing.T) {
	var probes atomic.Int32
	probe := func(ctx context.Context) (int, []byte, error) {
		probes.Add(1)
		return http.StatusOK, nil, nil
	}
	s := NewSessionSentinel(3, probe, nil)
	for i := 0; i < 7; i++ {
		if err := s.Before(stubReq()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	// Expected probes at request indices 1, 4, 7 - that's three probes.
	if got := probes.Load(); got != 3 {
		t.Fatalf("probes after 7 calls = %d, want 3", got)
	}
}

func TestSessionSentinelLatchesOnNon200(t *testing.T) {
	probe := func(ctx context.Context) (int, []byte, error) {
		return http.StatusFound, []byte("<html>login</html>"), nil
	}
	s := NewSessionSentinel(50, probe, nil)
	err := s.Before(stubReq())
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("first call err = %v, want ErrSessionLost", err)
	}
	// Subsequent calls must keep returning the same sticky error without
	// re-firing the probe.
	var afterProbes atomic.Int32
	s.probe = func(ctx context.Context) (int, []byte, error) {
		afterProbes.Add(1)
		return http.StatusOK, nil, nil
	}
	for i := 0; i < 3; i++ {
		if err := s.Before(stubReq()); !errors.Is(err, ErrSessionLost) {
			t.Fatalf("post-latch call %d err = %v, want ErrSessionLost", i, err)
		}
	}
	if got := afterProbes.Load(); got != 0 {
		t.Fatalf("probe re-fired %d times after latching, want 0", got)
	}
}

func TestSessionSentinelLatchesOnTransportError(t *testing.T) {
	boom := errors.New("dial: connection refused")
	probe := func(ctx context.Context) (int, []byte, error) {
		return 0, nil, boom
	}
	s := NewSessionSentinel(50, probe, nil)
	err := s.Before(stubReq())
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("err = %v, want ErrSessionLost", err)
	}
}

func TestSessionSentinelRegexMatch(t *testing.T) {
	probe := func(ctx context.Context) (int, []byte, error) {
		return http.StatusOK, []byte(`<a href="/logout">Sign out</a>`), nil
	}
	s := NewSessionSentinel(50, probe, regexp.MustCompile(`(?i)sign\s*out`))
	if err := s.Before(stubReq()); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestSessionSentinelRegexMismatch(t *testing.T) {
	probe := func(ctx context.Context) (int, []byte, error) {
		return http.StatusOK, []byte(`<form action="/login">Please sign in</form>`), nil
	}
	s := NewSessionSentinel(50, probe, regexp.MustCompile(`(?i)sign\s*out`))
	err := s.Before(stubReq())
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("err = %v, want ErrSessionLost", err)
	}
}

// End-to-end: a sentinel installed on a real Client must halt the Client.Do
// loop once it latches, returning ErrSessionLost without contacting the
// upstream server.
func TestSessionSentinelHaltsClient(t *testing.T) {
	var serverHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	probe := func(ctx context.Context) (int, []byte, error) {
		return http.StatusForbidden, nil, nil
	}
	c := New(Config{
		UserAgent:   "test",
		Middlewares: []RequestMiddleware{NewSessionSentinel(50, probe, nil)},
	})
	_, err := c.Get(context.Background(), srv.URL)
	if !errors.Is(err, ErrSessionLost) {
		t.Fatalf("err = %v, want ErrSessionLost", err)
	}
	if got := serverHits.Load(); got != 0 {
		t.Fatalf("server hit %d times, want 0 (sentinel should short-circuit)", got)
	}
}
