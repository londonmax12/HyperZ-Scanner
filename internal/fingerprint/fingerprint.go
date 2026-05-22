// Package fingerprint identifies the server software, language, framework,
// CMS, CDN, and WAF behind a host so checks can gate themselves and skip
// targets where they don't apply.
//
// Detection is best-effort and based on cheap signals: response headers,
// Set-Cookie names, and a bounded HTML body scan. One GET per host, cached
// for the lifetime of the detector, so a crawl that yields 200 pages on
// one host still costs exactly one fingerprint request.
package fingerprint

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
)

const defaultMaxBodyBytes = 256 << 10 // 256 KiB - enough for <head> in practice

// Stack is the detected technology profile for a host. Empty strings mean
// "unknown", not "absent"; a real Apache box might still report Server=""
// if the operator stripped it.
type Stack struct {
	Server    string `json:"server,omitempty"`    // nginx, apache, iis, caddy, openresty
	Language  string `json:"language,omitempty"`  // php, java, dotnet, ruby, python, node, go
	Framework string `json:"framework,omitempty"` // rails, django, laravel, express, asp.net, nextjs
	CMS       string `json:"cms,omitempty"`       // wordpress, drupal, joomla, magento, ghost
	CDN       string `json:"cdn,omitempty"`       // cloudflare, akamai, fastly, cloudfront
	WAF       string `json:"waf,omitempty"`       // cloudflare, akamai, sucuri, incapsula, aws

	// Versions holds version strings extracted from response headers or
	// body, keyed by the same lowercased category names Has accepts:
	// "server", "language", "framework", "cms", "cdn", "waf". A missing
	// or empty entry means "unknown" - gating checks must distinguish
	// that from "confirmed safe" via CompareVersion's ok return.
	Versions map[string]string `json:"versions,omitempty"`

	// Signals lists the matched rule labels (e.g. "header:Server~nginx",
	// "cookie:PHPSESSID") for inclusion in finding evidence and debug logs.
	Signals []string `json:"signals,omitempty"`

	// Confidence is the fraction of identifier categories populated, in
	// [0, 1]. It's a crude self-rating: gated checks should not refuse to
	// run based on it alone, but reporters can surface it to the user.
	Confidence float64 `json:"confidence"`
}

// Matches reports whether any of values equals one of the populated
// identifier fields (case-insensitive). Use it for OR-style gating:
// stack.Matches("wordpress", "drupal", "joomla").
func (s Stack) Matches(values ...string) bool {
	for _, v := range values {
		v = strings.ToLower(v)
		switch v {
		case strings.ToLower(s.Server),
			strings.ToLower(s.Language),
			strings.ToLower(s.Framework),
			strings.ToLower(s.CMS),
			strings.ToLower(s.CDN),
			strings.ToLower(s.WAF):
			if v != "" {
				return true
			}
		}
	}
	return false
}

// Has reports whether the named field equals one of values
// (case-insensitive). field is one of: server, language, framework, cms,
// cdn, waf. An unknown field name returns false.
func (s Stack) Has(field string, values ...string) bool {
	var got string
	switch strings.ToLower(field) {
	case "server":
		got = s.Server
	case "language":
		got = s.Language
	case "framework":
		got = s.Framework
	case "cms":
		got = s.CMS
	case "cdn":
		got = s.CDN
	case "waf":
		got = s.WAF
	default:
		return false
	}
	got = strings.ToLower(got)
	if got == "" {
		return false
	}
	for _, v := range values {
		if strings.ToLower(v) == got {
			return true
		}
	}
	return false
}

// CompareVersion compares the version stored under field against other.
// Returns (-1, true), (0, true), or (1, true) when the stored version is
// less than, equal to, or greater than other. Returns (0, false) when
// the version is unknown for that field or either side fails to parse.
//
// Gating callers should treat ok=false as "don't run" rather than "not
// vulnerable" - absence of a version is not proof of safety.
//
// Parsing is loose: leading digits per dot-separated segment are
// compared as integers, shorter versions are zero-padded, and any
// non-numeric suffix on a segment (e.g. "-rc1", "ubuntu1") is dropped.
// Suitable for header-emitted version strings; not full semver.
func (s Stack) CompareVersion(field, other string) (cmp int, ok bool) {
	have, exists := s.Versions[strings.ToLower(field)]
	if !exists || have == "" {
		return 0, false
	}
	a, ok1 := parseVersion(have)
	b, ok2 := parseVersion(other)
	if !ok1 || !ok2 {
		return 0, false
	}
	return compareVersions(a, b), true
}

func parseVersion(v string) ([]int, bool) {
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		i := 0
		for i < len(p) && p[i] >= '0' && p[i] <= '9' {
			i++
		}
		if i == 0 {
			return nil, false
		}
		n, err := strconv.Atoi(p[:i])
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func compareVersions(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// Summary renders a one-line human-readable summary, "key=value key=value
// ...", suitable for log output. Empty fields are omitted. When a version
// is known for a field, it's appended with a slash: "server=nginx/1.25.0".
func (s Stack) Summary() string {
	var parts []string
	add := func(k, v string) {
		if v == "" {
			return
		}
		if ver := s.Versions[k]; ver != "" {
			parts = append(parts, k+"="+v+"/"+ver)
			return
		}
		parts = append(parts, k+"="+v)
	}
	add("server", s.Server)
	add("language", s.Language)
	add("framework", s.Framework)
	add("cms", s.CMS)
	add("cdn", s.CDN)
	add("waf", s.WAF)
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " ")
}

// StackGated is optionally implemented by checks that should only run
// against certain stacks. Scanner queries it via type assertion - checks
// that don't implement it are treated as stack-agnostic (always run).
//
// stack is never nil when AppliesTo is called: detection failures cause
// the scanner to skip gating entirely rather than passing a sentinel.
type StackGated interface {
	AppliesTo(stack *Stack) bool
}

// Detector fingerprints hosts and caches the result. Safe for concurrent
// use; the per-host sync.Once ensures only one GET fires per host even
// under heavy parallel scanning.
type Detector struct {
	client       *httpclient.Client
	cache        sync.Map // host -> *cacheEntry
	maxBodyBytes int64
	onDetect     func(host string, stack *Stack)
}

type cacheEntry struct {
	once  sync.Once
	stack *Stack
	err   error
}

type Option func(*Detector)

// WithMaxBodyBytes caps the body read during HTML signal detection.
// 0 → default (256 KiB).
func WithMaxBodyBytes(n int64) Option {
	return func(d *Detector) {
		if n > 0 {
			d.maxBodyBytes = n
		}
	}
}

// WithOnDetect installs a callback invoked once per unique host the first
// time fingerprinting succeeds. Useful for logging "[fingerprint] host=…"
// without printing duplicates per crawled page.
func WithOnDetect(fn func(host string, stack *Stack)) Option {
	return func(d *Detector) { d.onDetect = fn }
}

func New(client *httpclient.Client, opts ...Option) *Detector {
	d := &Detector{client: client, maxBodyBytes: defaultMaxBodyBytes}
	for _, o := range opts {
		o(d)
	}
	return d
}

// Detect fingerprints the host of p. Repeat calls for the same host:port
// return the cached stack. An unparseable URL yields an empty stack and a
// non-nil error. Network failures are returned as-is - the caller decides
// whether to soft-fail.
//
// When p already carries the response (p.Headers non-nil), Detect classifies
// from that snapshot rather than issuing a fresh GET. This is the load-
// bearing optimization on a crawl: every Page from a host shares one
// fingerprint cache slot, and the slot is populated from whichever Page
// arrives first - no extra request needed.
func (d *Detector) Detect(ctx context.Context, p page.Page) (*Stack, error) {
	u, err := url.Parse(p.URL)
	if err != nil || u.Host == "" {
		return &Stack{}, err
	}
	key := u.Scheme + "://" + u.Host

	v, _ := d.cache.LoadOrStore(key, &cacheEntry{})
	entry := v.(*cacheEntry)
	entry.once.Do(func() {
		entry.stack, entry.err = d.detect(ctx, p)
		if entry.err == nil && d.onDetect != nil {
			d.onDetect(u.Host, entry.stack)
		}
	})
	return entry.stack, entry.err
}

// detect runs classification on p. If p has no captured headers (e.g. the
// caller built it from a bare URL) we fetch the URL ourselves; otherwise
// we reuse what the crawler already saw, which is the common case.
func (d *Detector) detect(ctx context.Context, p page.Page) (*Stack, error) {
	if p.Headers != nil {
		return classifyHeaders(p.Headers, p.Status, p.Body), nil
	}
	resp, err := d.client.Get(ctx, p.URL)
	if err != nil {
		return &Stack{}, err
	}
	defer resp.Body.Close()

	var body []byte
	if isHTML(resp.Header.Get("Content-Type")) {
		body, _ = httpclient.ReadBody(resp, d.maxBodyBytes)
	}
	return classify(resp, body), nil
}

// classifyHeaders is the response-less classify path: when we already have
// the response (from the crawler's Page) we can walk the same rule tables
// without a live *http.Response.
func classifyHeaders(headers http.Header, status int, body []byte) *Stack {
	resp := &http.Response{
		StatusCode: status,
		Header:     headers,
	}
	if !isHTML(headers.Get("Content-Type")) {
		// Mirror the live-fetch path: only HTML bodies are passed through
		// the body rules. Other content (JSON, images) carries no useful
		// fingerprint signal here.
		body = nil
	}
	return classify(resp, body)
}

func isHTML(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

// classify walks the rule tables against a response and body and returns
// the resulting Stack. Pulled out for unit testing without spinning up
// an httptest server for every signal combination.
func classify(resp *http.Response, body []byte) *Stack {
	s := &Stack{}

	for _, r := range headerRules {
		v := resp.Header.Get(r.header)
		if v == "" {
			continue
		}
		if r.needle != "" && !strings.Contains(strings.ToLower(v), strings.ToLower(r.needle)) {
			continue
		}
		r.set(s)
		s.Signals = append(s.Signals, "header:"+r.header+"~"+r.label())
		if r.verField != "" {
			if m := versionPattern.FindString(v); m != "" {
				setVersion(s, r.verField, m)
			}
		}
	}

	for _, c := range resp.Cookies() {
		name := strings.ToLower(c.Name)
		for _, r := range cookieRules {
			if !r.match(name) {
				continue
			}
			r.set(s)
			s.Signals = append(s.Signals, "cookie:"+c.Name)
		}
	}

	if len(body) > 0 {
		for _, r := range bodyRules {
			m := r.re.FindSubmatch(body)
			if m == nil {
				continue
			}
			r.set(s)
			s.Signals = append(s.Signals, "body:"+r.label)
			if r.verField != "" && len(m) > 1 && len(m[1]) > 0 {
				setVersion(s, r.verField, string(m[1]))
			}
		}
	}

	s.Confidence = confidenceOf(s)
	return s
}

func confidenceOf(s *Stack) float64 {
	const categories = 6.0
	n := 0
	for _, v := range []string{s.Server, s.Language, s.Framework, s.CMS, s.CDN, s.WAF} {
		if v != "" {
			n++
		}
	}
	return float64(n) / categories
}
