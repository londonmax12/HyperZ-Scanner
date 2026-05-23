package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync"
)

// ErrSessionLost is wrapped by every error SessionSentinel returns once it has
// latched. Callers can errors.Is(err, ErrSessionLost) to distinguish a dead
// session from other middleware failures.
var ErrSessionLost = errors.New("session lost")

// SessionProbe is the liveness check SessionSentinel fires. It issues its own
// request (typically a GET to a known-authenticated URL) and returns the
// observed status code and response body.
//
// The probe must NOT recurse through the same Client the sentinel is
// installed in - that would re-enter SessionSentinel.Before and loop until
// the stack runs out. Use the underlying *http.Client (or a stripped clone
// that shares the jar) instead.
type SessionProbe func(ctx context.Context) (status int, body []byte, err error)

// SessionSentinel is a RequestMiddleware that asserts the scanner's session
// is still alive on a fixed cadence. Every `every` outbound requests it fires
// a probe; on failure (transport error, non-200, or body regex mismatch when
// configured) it latches a sticky ErrSessionLost and every subsequent Before
// returns the same error so the scan halts deterministically instead of
// silently turning into anonymous traffic.
//
// The sentinel always probes on the first request so a broken session is
// caught before the scan does any real work, then again at requests
// every+1, 2*every+1, and so on.
type SessionSentinel struct {
	every     int64
	probe     SessionProbe
	matchBody *regexp.Regexp

	mu    sync.Mutex
	count int64
	lost  error
}

// NewSessionSentinel builds a sentinel that probes every `every` requests
// (values <= 0 default to 50). matchBody, when non-nil, must match the probe
// body for the probe to pass; otherwise the sentinel only checks status==200.
func NewSessionSentinel(every int, probe SessionProbe, matchBody *regexp.Regexp) *SessionSentinel {
	if every <= 0 {
		every = 50
	}
	return &SessionSentinel{
		every:     int64(every),
		probe:     probe,
		matchBody: matchBody,
	}
}

// Before is RequestMiddleware.Before. Counter and latched error live behind a
// single mutex so the probe trigger and the sticky-error read can't race when
// multiple scan workers cross the boundary at the same time.
func (s *SessionSentinel) Before(req *http.Request) error {
	s.mu.Lock()
	if s.lost != nil {
		err := s.lost
		s.mu.Unlock()
		return err
	}
	s.count++
	n := s.count
	s.mu.Unlock()
	if (n-1)%s.every != 0 {
		return nil
	}
	status, body, err := s.probe(req.Context())
	if err != nil {
		return s.setLost(fmt.Errorf("%w: probe failed at request %d: %v", ErrSessionLost, n, err))
	}
	if status != http.StatusOK {
		return s.setLost(fmt.Errorf("%w: probe returned status %d at request %d", ErrSessionLost, status, n))
	}
	if s.matchBody != nil && !s.matchBody.Match(body) {
		return s.setLost(fmt.Errorf("%w: probe body did not match expected pattern at request %d", ErrSessionLost, n))
	}
	return nil
}

func (s *SessionSentinel) setLost(err error) error {
	s.mu.Lock()
	if s.lost == nil {
		s.lost = err
	}
	out := s.lost
	s.mu.Unlock()
	return out
}
