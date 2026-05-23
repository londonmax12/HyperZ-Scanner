package checks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestEnsureResponseReusesProducerSnapshot(t *testing.T) {
	// When the producer (crawler) already populated Headers, ensureResponse
	// must not fire an HTTP request - that's the whole point of carrying
	// the response on page.Page.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	h := http.Header{}
	h.Set("Server", "nginx/1.18.0")
	p := page.Page{
		URL:     srv.URL,
		Status:  200,
		Headers: h,
		Body:    []byte("hi"),
		Fetched: true,
	}

	snap, err := ensureResponse(context.Background(), newTestClient(t), p, 0)
	if err != nil {
		t.Fatalf("ensureResponse: %v", err)
	}
	if got := snap.Headers.Get("Server"); got != "nginx/1.18.0" {
		t.Errorf("Server header = %q, want nginx/1.18.0", got)
	}
	if string(snap.Body) != "hi" {
		t.Errorf("Body = %q, want hi", snap.Body)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("server saw %d requests, want 0 (snapshot should be reused)", n)
	}
}

func TestEnsureResponseShortCircuitsOnFetchedButHeaderless(t *testing.T) {
	// Crawler fail path: it tried, got nothing, set Fetched=true and left
	// Headers nil. ensureResponse must return ErrFetchAlreadyFailed without
	// issuing a retry - otherwise N passive checks against a dead host turn
	// 1 wasted request into N.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	p := page.Page{URL: srv.URL, Fetched: true}

	_, err := ensureResponse(context.Background(), newTestClient(t), p, 0)
	if !errors.Is(err, ErrFetchAlreadyFailed) {
		t.Fatalf("err = %v, want ErrFetchAlreadyFailed", err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("server saw %d requests on short-circuit path, want 0", n)
	}
}

func TestEnsureResponseFetchesWhenNotFetched(t *testing.T) {
	// No-crawl path / page.FromURL / tests build pages with Fetched=false.
	// ensureResponse must still issue the GET in that case - short-circuiting
	// only kicks in when the producer has already tried.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Server", "test")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.FromURL(srv.URL)
	if p.Fetched {
		t.Fatal("page.FromURL must leave Fetched=false; otherwise no-crawl path breaks")
	}

	snap, err := ensureResponse(context.Background(), newTestClient(t), p, 0)
	if err != nil {
		t.Fatalf("ensureResponse: %v", err)
	}
	if snap.Headers.Get("Server") != "test" {
		t.Errorf("Server header = %q, want test", snap.Headers.Get("Server"))
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("server saw %d requests, want 1", n)
	}
}
