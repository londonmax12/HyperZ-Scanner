package proxy

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

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

// hostPortRE matches host:port tokens - used by the scraper to pull proxies
// out of mixed-format response bodies. Hostnames are 1..255 chars of letters,
// digits, dots, or hyphens; port is 1..5 digits.
var hostPortRE = regexp.MustCompile(`(?m)\b([a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}):(\d{1,5})\b`)

// extractHostPorts pulls host:port pairs out of arbitrary text. It's tolerant
// of common proxy-list formats (plain text, CSV-ish, one per line with junk).
func extractHostPorts(text string) []string {
	matches := hostPortRE.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1]+":"+m[2])
	}
	return out
}
