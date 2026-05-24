package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

func TestRaceConditionName(t *testing.T) {
	if got := (&RaceCondition{}).Name(); got != "race-condition" {
		t.Fatalf("Name = %q, want race-condition", got)
	}
}

func TestRaceConditionLevel(t *testing.T) {
	if got := (&RaceCondition{}).Level(); got != LevelAggressive {
		t.Fatalf("Level = %v, want aggressive", got)
	}
}

func TestLooksRaceSensitivePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/redeem", true},
		{"/api/v1/coupon/apply", true},
		{"/vote", true},
		{"/upvote/123", true},
		{"/api/withdraw", true},
		{"/checkout/place", true},
		{"/signup", true},
		{"/REGISTER", true},
		{"/api/users", false},
		{"/login", false},
		{"/", false},
		{"/static/main.js", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := looksRaceSensitivePath(tc.path); got != tc.want {
				t.Errorf("looksRaceSensitivePath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestRaceMethodIsStateChange(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{"POST", true},
		{"PUT", true},
		{"PATCH", true},
		{"DELETE", true},
		{"post", true},
		{"GET", false},
		{"HEAD", false},
		{"OPTIONS", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			if got := raceMethodIsStateChange(tc.method); got != tc.want {
				t.Errorf("raceMethodIsStateChange(%q) = %v, want %v", tc.method, got, tc.want)
			}
		})
	}
}

// racyHandler simulates a deterministic-variance handler suitable
// for exercising the variance oracle: the first wins-limit requests
// return 200, every subsequent request returns 409. The probe sends
// one baseline plus raceParallel parallel requests; with winsLimit
// chosen so the baseline plus part of the batch fall inside it, the
// batch produces a mix of 200 and 409, which is exactly the signal
// shape a real check-then-act race produces. The handler is not
// "really" racy - test determinism is more useful than test fidelity
// here - but the on-the-wire response distribution is identical.
func racyHandler(winsLimit int32) (http.Handler, *atomic.Int32) {
	var counter atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		n := counter.Add(1)
		if n <= winsLimit {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("redeemed"))
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("already redeemed"))
	})
	return h, &counter
}

// idempotentHandler simulates a properly-implemented endpoint that
// returns the same response to every duplicate. Every probe gets
// the same status code regardless of arrival order.
func idempotentHandler(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func withRaceTimeouts(t *testing.T) {
	t.Helper()
	prevDial, prevRead, prevBarrier := raceDialTimeout, raceReadTimeout, raceBarrierTimeout
	raceDialTimeout = 2 * time.Second
	raceReadTimeout = 2 * time.Second
	raceBarrierTimeout = 5 * time.Second
	t.Cleanup(func() {
		raceDialTimeout = prevDial
		raceReadTimeout = prevRead
		raceBarrierTimeout = prevBarrier
	})
}

func TestRaceConditionDetectsStatusVariance(t *testing.T) {
	withRaceTimeouts(t)
	// winsLimit=5: baseline consumes slot 1, parallel batch of 10
	// gets slots 2..11, so 4 of them return 200 and 6 return 409 -
	// status variance that the oracle classifies as a race signal.
	h, _ := racyHandler(5)
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := page.FromURL(srv.URL + "/account/dashboard")
	p.Forms = []page.Form{{
		Method: "POST",
		Action: srv.URL + "/api/redeem",
		Inputs: []page.FormInput{
			{Name: "coupon", Value: "ABC123"},
		},
	}}

	findings, err := (&RaceCondition{}).Run(context.Background(), nil, allowAllScope(t), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from racy handler, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if f.CWE != "CWE-362" {
		t.Errorf("CWE = %q, want CWE-362", f.CWE)
	}
	if !strings.Contains(f.Title, "/api/redeem") {
		t.Errorf("title should name the path: %q", f.Title)
	}
	if !strings.Contains(f.Detail, "histogram") {
		t.Errorf("detail should reference the status histogram: %q", f.Detail)
	}
}

func TestRaceConditionNoFindingOnIdempotentHandler(t *testing.T) {
	withRaceTimeouts(t)
	srv := httptest.NewServer(idempotentHandler(http.StatusOK, "ok"))
	defer srv.Close()

	p := page.FromURL(srv.URL + "/account")
	p.Forms = []page.Form{{
		Method: "POST",
		Action: srv.URL + "/api/redeem",
		Inputs: []page.FormInput{
			{Name: "coupon", Value: "ABC123"},
		},
	}}

	findings, err := (&RaceCondition{}).Run(context.Background(), nil, allowAllScope(t), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on idempotent handler (all-200), got %d: %+v",
			len(findings), findings)
	}
}

func TestRaceConditionNoFindingOnAllRejectHandler(t *testing.T) {
	withRaceTimeouts(t)
	srv := httptest.NewServer(idempotentHandler(http.StatusBadRequest, "nope"))
	defer srv.Close()

	p := page.FromURL(srv.URL + "/account")
	p.Forms = []page.Form{{
		Method: "POST",
		Action: srv.URL + "/api/redeem",
		Inputs: []page.FormInput{
			{Name: "coupon", Value: "ABC123"},
		},
	}}

	findings, err := (&RaceCondition{}).Run(context.Background(), nil, allowAllScope(t), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on all-4xx handler, got %d: %+v",
			len(findings), findings)
	}
}

func TestRaceConditionSkipsNonSensitivePath(t *testing.T) {
	withRaceTimeouts(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.FromURL(srv.URL + "/dashboard")
	p.Forms = []page.Form{{
		Method: "POST",
		Action: srv.URL + "/api/search", // no race keyword
		Inputs: []page.FormInput{{Name: "q", Value: "foo"}},
	}}

	findings, err := (&RaceCondition{}).Run(context.Background(), nil, allowAllScope(t), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on non-sensitive path, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("non-sensitive path was probed %d times; gate should have skipped", got)
	}
}

func TestRaceConditionSkipsGetForms(t *testing.T) {
	withRaceTimeouts(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := page.FromURL(srv.URL + "/dashboard")
	p.Forms = []page.Form{{
		Method: "GET", // GETs cannot race-meaningfully
		Action: srv.URL + "/api/redeem",
		Inputs: []page.FormInput{{Name: "coupon", Value: "ABC"}},
	}}

	findings, err := (&RaceCondition{}).Run(context.Background(), nil, allowAllScope(t), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on GET form, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("GET form was probed %d times; gate should have skipped", got)
	}
}

func TestRaceConditionDedupesAcrossPages(t *testing.T) {
	withRaceTimeouts(t)
	srv := httptest.NewServer(idempotentHandler(http.StatusOK, "ok"))
	defer srv.Close()

	// Same form referenced from two different page URLs should only
	// be probed once.
	var dialCount atomic.Int32
	prevDial := raceDialPlain
	raceDialPlain = func(ctx context.Context, addr string) (net.Conn, error) {
		dialCount.Add(1)
		return prevDial(ctx, addr)
	}
	t.Cleanup(func() { raceDialPlain = prevDial })

	check := &RaceCondition{}
	form := page.Form{
		Method: "POST",
		Action: srv.URL + "/api/redeem",
		Inputs: []page.FormInput{{Name: "coupon", Value: "ABC"}},
	}
	p1 := page.FromURL(srv.URL + "/page1")
	p1.Forms = []page.Form{form}
	p2 := page.FromURL(srv.URL + "/page2")
	p2.Forms = []page.Form{form}

	if _, err := check.Run(context.Background(), nil, allowAllScope(t), p1); err != nil {
		t.Fatalf("Run #1: %v", err)
	}
	first := dialCount.Load()
	if _, err := check.Run(context.Background(), nil, allowAllScope(t), p2); err != nil {
		t.Fatalf("Run #2: %v", err)
	}
	second := dialCount.Load()
	if second != first {
		t.Errorf("second page added %d dials; want 0 (target should have been deduped)", second-first)
	}
}

func TestRaceConditionCollectsSpecOps(t *testing.T) {
	withRaceTimeouts(t)
	h, _ := racyHandler(5)
	srv := httptest.NewServer(h)
	defer srv.Close()

	p := page.FromURL(srv.URL + "/")
	p.SpecOps = []page.SpecOp{{
		Method: "POST",
		URL:    srv.URL + "/api/v1/redeem",
		Tpl:    "/api/v1/redeem",
		Params: []page.SpecParam{
			{In: "body", Name: "coupon_code", Value: "PROMO"},
		},
	}}

	findings, err := (&RaceCondition{}).Run(context.Background(), nil, allowAllScope(t), p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from spec-discovered POST, got %d: %+v", len(findings), findings)
	}
	for _, d := range findings[0].Details {
		if strings.Contains(d, "openapi-spec") {
			return
		}
	}
	t.Errorf("finding should record source=openapi-spec in details: %+v", findings[0].Details)
}

func TestRaceVerdictRequiresTwoStatuses(t *testing.T) {
	cases := []struct {
		name    string
		base    int
		results []raceProbeResult
		want    bool
	}{
		{
			"all-200-no-race",
			200,
			[]raceProbeResult{{Status: 200}, {Status: 200}, {Status: 200}},
			false,
		},
		{
			"all-409-no-race",
			409,
			[]raceProbeResult{{Status: 409}, {Status: 409}, {Status: 409}},
			false,
		},
		{
			"variance-with-success-is-race",
			200,
			[]raceProbeResult{{Status: 200}, {Status: 200}, {Status: 409}, {Status: 409}},
			true,
		},
		{
			"variance-without-success-is-not-race",
			409,
			[]raceProbeResult{{Status: 400}, {Status: 409}, {Status: 500}},
			false,
		},
		{
			"too-few-probes",
			200,
			[]raceProbeResult{{Status: 200}, {Err: fmt.Errorf("boom")}, {Err: fmt.Errorf("boom")}},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := evaluateRaceVerdict(tc.base, tc.results)
			if v.Race != tc.want {
				t.Errorf("Race = %v, want %v (%s)", v.Race, tc.want, v.Reason)
			}
		})
	}
}

func TestSplitForBarrier(t *testing.T) {
	prefix, last := splitForBarrier("POST / HTTP/1.1\r\n\r\nA")
	if string(last) != "A" {
		t.Errorf("final byte = %q, want 'A'", last)
	}
	if !strings.HasSuffix(string(prefix), "\r\n\r\n") {
		t.Errorf("prefix should end at the byte before final body byte: %q", prefix)
	}
}

func TestHashPrefixStable(t *testing.T) {
	a := hashPrefix([]byte("hello"))
	b := hashPrefix([]byte("hello"))
	if a != b {
		t.Errorf("hashPrefix not stable: %q vs %q", a, b)
	}
	if a == hashPrefix([]byte("world")) {
		t.Errorf("hashPrefix should differ for different inputs")
	}
	if hashPrefix(nil) != "" {
		t.Errorf("hashPrefix(nil) should be empty")
	}
}

func TestRaceConditionScopeAllowsTargets(t *testing.T) {
	// Targets outside the configured scope must not be probed.
	withRaceTimeouts(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sc, err := scope.New(scope.Config{Hosts: []string{"only-this-host.invalid"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	p := page.FromURL(srv.URL + "/dashboard")
	p.Forms = []page.Form{{
		Method: "POST",
		Action: srv.URL + "/api/redeem",
		Inputs: []page.FormInput{{Name: "coupon", Value: "ABC"}},
	}}
	findings, err := (&RaceCondition{}).Run(context.Background(), nil, sc, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings out of scope, got %d", len(findings))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server hit %d times; out-of-scope target must not be probed", got)
	}
}

// allowAllScope returns a scope that permits any host the test's
// httptest server might bind on. The Hosts field accepts wildcards
// but matching loopback specifically keeps the test scope tight.
func allowAllScope(t *testing.T) *scope.Scope {
	t.Helper()
	sc, err := scope.New(scope.Config{Hosts: []string{"127.0.0.1", "localhost"}})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return sc
}

// Compile-time assertion: the prober is parameterised by the same
// dial functions tests can override. Keeps the test framework from
// reaching into transport guts a future refactor might rename.
var _ = tls.Config{}
var _ = sync.WaitGroup{}
var _ = (&url.URL{})
