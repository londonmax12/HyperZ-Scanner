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
	"strings"
	"sync"

	"github.com/londonball/hyperz/internal/httpclient"
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

// Summary renders a one-line human-readable summary, "key=value key=value
// ...", suitable for log output. Empty fields are omitted.
func (s Stack) Summary() string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
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

// Detect fingerprints the host of target. Repeat calls for the same
// host:port return the cached stack. An unparseable URL yields an empty
// stack and a non-nil error. Network failures are returned as-is - the
// caller decides whether to soft-fail.
func (d *Detector) Detect(ctx context.Context, target string) (*Stack, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return &Stack{}, err
	}
	key := u.Scheme + "://" + u.Host

	v, _ := d.cache.LoadOrStore(key, &cacheEntry{})
	entry := v.(*cacheEntry)
	entry.once.Do(func() {
		entry.stack, entry.err = d.detect(ctx, target)
		if entry.err == nil && d.onDetect != nil {
			d.onDetect(u.Host, entry.stack)
		}
	})
	return entry.stack, entry.err
}

func (d *Detector) detect(ctx context.Context, target string) (*Stack, error) {
	resp, err := d.client.Get(ctx, target)
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
			if !r.re.Match(body) {
				continue
			}
			r.set(s)
			s.Signals = append(s.Signals, "body:"+r.label)
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
