// Package scope describes the bounds of a scan: which hosts may be hit, on
// which ports, which paths are in/out, and how far the crawler may follow
// links. One Scope value is built from CLI flags and threaded into the
// crawler (to gate link discovery) and into each check (so active probes
// don't reach out beyond what the user authorized).
//
// A nil *Scope is treated as fully permissive; useful in tests and in the
// single-target, no-crawl path where the user supplied URLs are already the
// universe of work.
package scope

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type Scope struct {
	hosts       map[string]struct{}
	portMin     int
	portMax     int
	pathInclude []*regexp.Regexp
	pathExclude []*regexp.Regexp
	maxDepth    int
}

// Config is the user-supplied form. New compiles it into a Scope.
//
// Hosts: lowercased hostnames (no port). Empty → any host allowed; callers
// that want "same-host as seeds" behavior should AllowHost the seed hosts
// before handing the Scope off.
//
// Ports: either "N" (single port) or "lo-hi" (inclusive range). Empty →
// 1..65535. The matched port is u.Port() when present, else the default for
// u.Scheme (http=80, https=443).
//
// PathInclude/PathExclude: regexes matched against u.EscapedPath(). Exclude
// wins. Empty include → no inclusion filter (path passes unless excluded).
//
// MaxDepth: cap on crawl distance from any seed. -1 → unlimited; 0 → seeds
// only.
type Config struct {
	Hosts       []string
	Ports       string
	PathInclude []string
	PathExclude []string
	MaxDepth    int
}

func New(cfg Config) (*Scope, error) {
	s := &Scope{
		hosts:    map[string]struct{}{},
		portMin:  1,
		portMax:  65535,
		maxDepth: cfg.MaxDepth,
	}
	for _, h := range cfg.Hosts {
		s.AllowHost(h)
	}
	if cfg.Ports != "" {
		lo, hi, err := parsePortRange(cfg.Ports)
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		s.portMin, s.portMax = lo, hi
	}
	for _, p := range cfg.PathInclude {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("path-include %q: %w", p, err)
		}
		s.pathInclude = append(s.pathInclude, re)
	}
	for _, p := range cfg.PathExclude {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("path-exclude %q: %w", p, err)
		}
		s.pathExclude = append(s.pathExclude, re)
	}
	return s, nil
}

// AllowHost adds a host to the allowlist. Safe to call on nil (no-op) so
// callers can blindly seed scope from CLI inputs.
func (s *Scope) AllowHost(h string) {
	if s == nil {
		return
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return
	}
	s.hosts[h] = struct{}{}
}

// Allows reports whether u falls within the scope. A nil Scope or nil URL
// is permissive - see the package doc.
func (s *Scope) Allows(u *url.URL) bool {
	if s == nil || u == nil {
		return true
	}
	if len(s.hosts) > 0 {
		if _, ok := s.hosts[strings.ToLower(u.Hostname())]; !ok {
			return false
		}
	}
	port := effectivePort(u)
	if port < s.portMin || port > s.portMax {
		return false
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	for _, re := range s.pathExclude {
		if re.MatchString(path) {
			return false
		}
	}
	if len(s.pathInclude) > 0 {
		matched := false
		for _, re := range s.pathInclude {
			if re.MatchString(path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// AllowsDepth reports whether a crawl at the given depth-from-seed is in
// scope. MaxDepth < 0 means unlimited.
func (s *Scope) AllowsDepth(depth int) bool {
	if s == nil || s.maxDepth < 0 {
		return true
	}
	return depth <= s.maxDepth
}

// MaxDepth returns the configured depth cap (or -1 for unlimited / nil scope).
func (s *Scope) MaxDepth() int {
	if s == nil {
		return -1
	}
	return s.maxDepth
}

// HasHosts reports whether the scope has any host allowlist configured.
// A nil Scope, or a Scope built with no Hosts, returns false - both
// represent the "open scope" mode where every host passes Allows.
// Active checks use this to distinguish operator-vetted scope (trust
// any same-scope host) from open scope (need a heuristic to avoid
// probing third-party endpoints referenced in body content).
func (s *Scope) HasHosts() bool {
	if s == nil {
		return false
	}
	return len(s.hosts) > 0
}

// Hosts returns a snapshot of the allowed-host set as a sorted slice, for
// logging and tests. Returns nil for an open scope (no host restriction).
func (s *Scope) Hosts() []string {
	if s == nil || len(s.hosts) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.hosts))
	for h := range s.hosts {
		out = append(out, h)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// SameSite reports whether two hostnames belong to the same registrable
// domain (eTLD+1 in Public Suffix List terms). app.target.com and
// ws.target.com share target.com and return true; app.target.com and
// target.co.uk share nothing and return false. Comparison is case-
// insensitive. Active probes use this as the "same organization"
// gate when the operator has not pinned a host allowlist - the
// hostname-equality alternative misses the very common pattern of
// offloading WebSockets / SSE to dedicated subdomains.
//
// Inputs that do not have a meaningful registrable domain (IP literals,
// bare hostnames without a public suffix like "localhost", or empty
// strings) fall back to case-insensitive exact equality. Two
// 127.0.0.1's are still the same target; an IP and a domain never are.
func SameSite(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	// IP literals never have a registrable domain. Two different IPs
	// are not "same site" even when they're on the same /24 - the
	// caller is asking about logical site identity, not network
	// adjacency. Falling back to exact match was already handled above.
	if net.ParseIP(a) != nil || net.ParseIP(b) != nil {
		return false
	}
	siteA, errA := publicsuffix.EffectiveTLDPlusOne(a)
	siteB, errB := publicsuffix.EffectiveTLDPlusOne(b)
	if errA != nil || errB != nil {
		// Either hostname is below the public suffix line (e.g.
		// "localhost", or a private TLD not in the PSL). We have no
		// principled way to call them same-site; only exact equality
		// counts, which was already checked above.
		return false
	}
	return siteA == siteB
}

func effectivePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	switch u.Scheme {
	case "https", "wss":
		return 443
	case "ftp":
		return 21
	}
	return 80
}

func parsePortRange(spec string) (int, int, error) {
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, fmt.Errorf("low port %q: %w", parts[0], err)
		}
		hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, 0, fmt.Errorf("high port %q: %w", parts[1], err)
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return 0, 0, fmt.Errorf("invalid range %d-%d", lo, hi)
		}
		return lo, hi, nil
	}
	n, err := strconv.Atoi(spec)
	if err != nil {
		return 0, 0, fmt.Errorf("port %q: %w", spec, err)
	}
	if n < 1 || n > 65535 {
		return 0, 0, fmt.Errorf("port %d out of 1-65535", n)
	}
	return n, n, nil
}
