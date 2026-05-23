package checks

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRecordExchangeCopiesRequestAndResponseSides(t *testing.T) {
	reqURL, _ := url.Parse("http://example.com/login")
	req := &http.Request{
		Method: http.MethodPost,
		URL:    reqURL,
		Header: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
	}
	resp := &http.Response{
		StatusCode: 200,
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Server": []string{"nginx"}},
	}
	ex := RecordExchange(req, []byte("user=a&pass=b"), false, resp, []byte("ok"), false)
	if ex == nil {
		t.Fatal("RecordExchange returned nil")
	}
	if ex.Method != http.MethodPost || ex.URL != "http://example.com/login" {
		t.Errorf("method/url = %q/%q", ex.Method, ex.URL)
	}
	if ex.Status != 200 || ex.Proto != "HTTP/1.1" {
		t.Errorf("status/proto = %d/%q", ex.Status, ex.Proto)
	}
	if ex.RequestHeaders.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("request header lost: %v", ex.RequestHeaders)
	}
	if ex.ResponseHeaders.Get("Server") != "nginx" {
		t.Errorf("response header lost: %v", ex.ResponseHeaders)
	}
	if ex.RequestBody != "user=a&pass=b" || ex.ResponseBody != "ok" {
		t.Errorf("bodies = %q / %q", ex.RequestBody, ex.ResponseBody)
	}
}

func TestRecordExchangeFlagsTruncation(t *testing.T) {
	req := &http.Request{Method: http.MethodPost, URL: &url.URL{Scheme: "http", Host: "x"}, Header: http.Header{}}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	ex := RecordExchange(req, []byte("partial-req"), true, resp, []byte("partial-resp"), true)
	if ex == nil {
		t.Fatal("RecordExchange returned nil")
	}
	if !ex.RequestBodyTruncated || !ex.ResponseBodyTruncated {
		t.Errorf("truncation flags lost: req=%v resp=%v",
			ex.RequestBodyTruncated, ex.ResponseBodyTruncated)
	}
}

func TestRecordExchangeFillsRequestFromResponseRequest(t *testing.T) {
	// Callers that only kept the *http.Response (e.g. client.Get returned)
	// should still get method/URL/headers populated via resp.Request.
	reqURL, _ := url.Parse("http://example.com/")
	resp := &http.Response{
		StatusCode: 404,
		Header:     http.Header{},
		Request: &http.Request{
			Method: http.MethodGet,
			URL:    reqURL,
			Header: http.Header{"X-Trace": []string{"abc"}},
		},
	}
	ex := RecordExchange(nil, nil, false, resp, nil, false)
	if ex.Method != http.MethodGet || ex.URL != "http://example.com/" {
		t.Errorf("missing method/url from resp.Request: %q/%q", ex.Method, ex.URL)
	}
	if ex.RequestHeaders.Get("X-Trace") != "abc" {
		t.Errorf("request headers from resp.Request lost: %v", ex.RequestHeaders)
	}
}

func TestRecordExchangeDeepCopiesHeaders(t *testing.T) {
	// Mutating the source headers after recording must not leak into the
	// captured Exchange - it's supposed to be a self-contained snapshot.
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "x"},
		Header: http.Header{"X-Trace": []string{"original"}},
	}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Server": []string{"nginx"}},
	}
	ex := RecordExchange(req, nil, false, resp, nil, false)
	req.Header.Set("X-Trace", "mutated")
	resp.Header.Set("Server", "apache")
	if ex.RequestHeaders.Get("X-Trace") != "original" {
		t.Errorf("request headers not cloned: %q", ex.RequestHeaders.Get("X-Trace"))
	}
	if ex.ResponseHeaders.Get("Server") != "nginx" {
		t.Errorf("response headers not cloned: %q", ex.ResponseHeaders.Get("Server"))
	}
}

func TestRecordExchangeReturnsNilWhenNothingToRecord(t *testing.T) {
	if got := RecordExchange(nil, nil, false, nil, nil, false); got != nil {
		t.Errorf("expected nil for empty input, got %+v", got)
	}
}

func TestStatusOfNilResponse(t *testing.T) {
	if got := statusOf(nil); got != 0 {
		t.Errorf("statusOf(nil) = %d, want 0", got)
	}
	if got := statusOf(&http.Response{StatusCode: 418}); got != 418 {
		t.Errorf("statusOf(418) = %d, want 418", got)
	}
}
