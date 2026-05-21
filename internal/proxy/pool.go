// Package proxy holds the proxy pool used by the HTTP client. The current
// implementation loads proxies from a list and hands them out round-robin;
// a follow-up PR will replace Next with health-aware smart cycling driven
// by per-proxy block rate.
package proxy

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

type Pool struct {
	proxies []*url.URL
	cursor  atomic.Uint64
}

func NewPool(proxies []*url.URL) *Pool {
	return &Pool{proxies: proxies}
}

func (p *Pool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.proxies)
}

// Next returns the next proxy in round-robin order, or nil if the pool is
// empty (in which case requests go direct).
func (p *Pool) Next() *url.URL {
	if p == nil || len(p.proxies) == 0 {
		return nil
	}
	i := p.cursor.Add(1) - 1
	return p.proxies[i%uint64(len(p.proxies))]
}

// ProxyFunc returns a function shaped for http.Transport.Proxy.
func (p *Pool) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) { return p.Next(), nil }
}

// Load parses inline proxy strings and an optional file (one entry per line,
// blank lines and lines starting with '#' ignored) into a deduped slice of
// proxy URLs. Bare host:port entries default to the http:// scheme.
func Load(inline []string, file string) ([]*url.URL, error) {
	seen := map[string]struct{}{}
	var out []*url.URL
	add := func(raw string, src string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return nil
		}
		u, err := parseProxy(raw)
		if err != nil {
			return fmt.Errorf("%s: %q: %w", src, raw, err)
		}
		key := u.String()
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		out = append(out, u)
		return nil
	}
	for _, raw := range inline {
		if err := add(raw, "proxy"); err != nil {
			return nil, err
		}
	}
	if file == "" {
		return out, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open proxies-file: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if err := add(sc.Text(), file); err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read proxies-file: %w", err)
	}
	return out, nil
}

func parseProxy(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	return u, nil
}
