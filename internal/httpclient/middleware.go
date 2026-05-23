package httpclient

import "net/http"

// RequestMiddleware runs just before each outbound request leaves the client.
// It can mutate the request in place (add a header, rewrite a form body,
// attach a refreshed CSRF token) or short-circuit the whole call by returning
// an error - useful for "the session is dead, halt the scan now" semantics.
//
// Middlewares run after the static User-Agent / ExtraHeaders / auth shims and
// before the budget + host limiter, so a middleware that fires its own
// internal request (e.g. fetching a fresh CSRF token) participates in the same
// limits as everything else.
//
// The interface stays narrow on purpose: more behaviour fits as more
// middlewares, not as more methods. Each implementation can hold its own
// state behind whatever locking it needs.
type RequestMiddleware interface {
	Before(*http.Request) error
}

// MiddlewareFunc adapts a plain function to RequestMiddleware so trivial
// in-test middlewares (counters, header stampers) don't need their own type.
type MiddlewareFunc func(*http.Request) error

func (f MiddlewareFunc) Before(req *http.Request) error { return f(req) }
