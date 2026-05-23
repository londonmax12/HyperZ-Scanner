package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMiddlewareRunsInOrder(t *testing.T) {
	var trail []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trail = append(trail, "transport:"+r.Header.Get("X-Trace"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mw1 := MiddlewareFunc(func(req *http.Request) error {
		trail = append(trail, "mw1")
		req.Header.Set("X-Trace", req.Header.Get("X-Trace")+"a")
		return nil
	})
	mw2 := MiddlewareFunc(func(req *http.Request) error {
		trail = append(trail, "mw2")
		req.Header.Set("X-Trace", req.Header.Get("X-Trace")+"b")
		return nil
	})
	c := New(Config{
		Timeout:     5 * time.Second,
		UserAgent:   "test",
		Middlewares: []RequestMiddleware{mw1, mw2},
	})
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	want := []string{"mw1", "mw2", "transport:ab"}
	if len(trail) != len(want) {
		t.Fatalf("trail = %v, want %v", trail, want)
	}
	for i := range want {
		if trail[i] != want[i] {
			t.Fatalf("trail[%d] = %q, want %q", i, trail[i], want[i])
		}
	}
}

func TestMiddlewareShortCircuit(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sentinel := errors.New("blocked by middleware")
	mw := MiddlewareFunc(func(req *http.Request) error { return sentinel })
	c := New(Config{
		Timeout:     5 * time.Second,
		UserAgent:   "test",
		Middlewares: []RequestMiddleware{mw},
	})
	_, err := c.Get(context.Background(), srv.URL)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if hit {
		t.Fatal("transport was called despite middleware short-circuit")
	}
}
