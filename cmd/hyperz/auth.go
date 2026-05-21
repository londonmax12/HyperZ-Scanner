package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/londonball/hyperz/internal/httpclient"
)

// applyAuthConfig pulls cookie/header/auth flags off the scan config and
// populates the httpclient.Config in place. The seed list is needed so
// unscoped --cookie values can be attached to every target host.
func applyAuthConfig(clientCfg *httpclient.Config, cfg *scanConfig, seeds []string, log *slog.Logger) error {
	basic, err := parseBasicAuth(cfg.authBasic)
	if err != nil {
		return err
	}
	bearer := strings.TrimSpace(cfg.authBearer)
	if basic != nil && bearer != "" {
		return fmt.Errorf("--auth-basic and --auth-bearer are mutually exclusive")
	}
	clientCfg.BasicAuth = basic
	clientCfg.BearerToken = bearer

	headers, err := parseExtraHeaders(cfg.headers)
	if err != nil {
		return err
	}
	clientCfg.ExtraHeaders = headers

	cliCookies, err := parseCookieSpecs(cfg.cookies)
	if err != nil {
		return err
	}
	var fileScoped, fileUnscoped []*http.Cookie
	if cfg.cookiesFile != "" {
		fileScoped, fileUnscoped, err = loadCookiesFile(cfg.cookiesFile)
		if err != nil {
			return err
		}
	}
	if len(cliCookies)+len(fileScoped)+len(fileUnscoped) == 0 {
		return nil
	}
	unscoped := append(cliCookies, fileUnscoped...)
	jar, err := newCookieJar(seeds, fileScoped, unscoped)
	if err != nil {
		return fmt.Errorf("init cookie jar: %w", err)
	}
	clientCfg.Jar = jar
	log.Info("cookie jar ready",
		"cli", len(cliCookies),
		"file_scoped", len(fileScoped),
		"file_unscoped", len(fileUnscoped))
	return nil
}

// parseBasicAuth splits "user:pass" into credentials. An empty value disables
// basic auth (returns nil, nil) so callers can use it directly with the flag.
func parseBasicAuth(s string) (*httpclient.BasicAuth, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return nil, fmt.Errorf("--auth-basic: expected user:pass, got %q", s)
	}
	return &httpclient.BasicAuth{Username: s[:i], Password: s[i+1:]}, nil
}

// parseExtraHeaders accepts one "Name: Value" entry per slice element and
// returns a Header. Empty/blank entries are skipped; malformed entries return
// an error so users notice flag typos rather than silently dropping headers.
func parseExtraHeaders(entries []string) (http.Header, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	h := http.Header{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		i := strings.IndexByte(e, ':')
		if i <= 0 {
			return nil, fmt.Errorf("--header: expected 'Name: Value', got %q", e)
		}
		name := strings.TrimSpace(e[:i])
		val := strings.TrimSpace(e[i+1:])
		if name == "" {
			return nil, fmt.Errorf("--header: empty name in %q", e)
		}
		h.Add(name, val)
	}
	return h, nil
}

// parseCookieSpecs accepts:
//   - "name=value"
//   - "name=value; name2=value2" (a Cookie header style list)
//
// Each parsed pair is returned as one *http.Cookie. Domain/Path are left
// unset; the caller scopes them to the seed hosts via newCookieJar.
func parseCookieSpecs(specs []string) ([]*http.Cookie, error) {
	var out []*http.Cookie
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		for _, pair := range strings.Split(s, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			i := strings.IndexByte(pair, '=')
			if i <= 0 {
				return nil, fmt.Errorf("--cookie: expected name=value, got %q", pair)
			}
			out = append(out, &http.Cookie{
				Name:  strings.TrimSpace(pair[:i]),
				Value: strings.TrimSpace(pair[i+1:]),
			})
		}
	}
	return out, nil
}

// loadCookiesFile reads cookies from path. Supports two formats, detected by
// content:
//
//   - Netscape cookie file (curl -b / browser export): tab-separated lines of
//     `domain<TAB>flag<TAB>path<TAB>secure<TAB>expires<TAB>name<TAB>value`.
//     Lines starting with '#' are comments (the magic header '# Netscape HTTP
//     Cookie File' is treated as a comment too).
//   - Plain `name=value` per line, optionally with a leading `domain ` token
//     (space-separated) to scope it. No `domain ` prefix means "apply to all
//     seed hosts" — same as --cookie.
//
// Blank lines and '#' comments are skipped in both formats.
func loadCookiesFile(path string) ([]*http.Cookie, []*http.Cookie, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open cookies-file: %w", err)
	}
	defer f.Close()

	var scoped, unscoped []*http.Cookie
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		// '#HttpOnly_' is a Netscape-format marker, not a comment.
		if strings.HasPrefix(trim, "#") && !strings.HasPrefix(trim, "#HttpOnly_") {
			continue
		}
		// Netscape format: at least 7 tab-separated fields.
		if fields := strings.Split(line, "\t"); len(fields) >= 7 {
			c, err := netscapeCookie(fields)
			if err != nil {
				return nil, nil, fmt.Errorf("cookies-file: %w", err)
			}
			scoped = append(scoped, c)
			continue
		}
		// Plain format. Optional leading "<domain> " scopes it.
		domain := ""
		rest := trim
		if i := strings.IndexAny(trim, " \t"); i > 0 {
			head := trim[:i]
			tail := strings.TrimSpace(trim[i+1:])
			if strings.Contains(tail, "=") && (strings.ContainsAny(head, ".") || head == "localhost") {
				domain = head
				rest = tail
			}
		}
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return nil, nil, fmt.Errorf("cookies-file: expected name=value, got %q", rest)
		}
		c := &http.Cookie{
			Name:   strings.TrimSpace(rest[:eq]),
			Value:  strings.TrimSpace(rest[eq+1:]),
			Domain: domain,
		}
		if domain == "" {
			unscoped = append(unscoped, c)
		} else {
			scoped = append(scoped, c)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("read cookies-file: %w", err)
	}
	return scoped, unscoped, nil
}

func netscapeCookie(fields []string) (*http.Cookie, error) {
	// domain  includeSubdomains  path  secure  expires  name  value
	domain := strings.TrimPrefix(fields[0], "#HttpOnly_")
	path := fields[2]
	secure := strings.EqualFold(strings.TrimSpace(fields[3]), "TRUE")
	name := fields[5]
	value := fields[6]
	if name == "" {
		return nil, fmt.Errorf("netscape entry missing cookie name")
	}
	c := &http.Cookie{
		Name:   name,
		Value:  value,
		Domain: domain,
		Path:   path,
		Secure: secure,
	}
	// expires=0 means "session" — leave Expires zero.
	if exp := strings.TrimSpace(fields[4]); exp != "" && exp != "0" {
		if secs, err := strconv.ParseInt(exp, 10, 64); err == nil && secs > 0 {
			c.Expires = time.Unix(secs, 0)
		}
	}
	return c, nil
}

// newCookieJar constructs a jar and seeds it. `scoped` cookies already carry
// a Domain; they're attached to a synthetic URL derived from that domain.
// `unscoped` cookies (from --cookie or a plain cookies-file) are attached to
// every seed host so they ride along with the scan.
func newCookieJar(seeds []string, scoped, unscoped []*http.Cookie) (http.CookieJar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	for _, c := range scoped {
		u, err := cookieURLForDomain(c.Domain, c.Path, c.Secure)
		if err != nil {
			return nil, err
		}
		jar.SetCookies(u, []*http.Cookie{c})
	}
	if len(unscoped) > 0 {
		seedURLs := uniqueHostURLs(seeds)
		for _, u := range seedURLs {
			jar.SetCookies(u, unscoped)
		}
	}
	return jar, nil
}

func cookieURLForDomain(domain, path string, secure bool) (*url.URL, error) {
	host := strings.TrimPrefix(domain, ".")
	if host == "" {
		return nil, fmt.Errorf("cookie has empty domain")
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	if path == "" {
		path = "/"
	}
	return url.Parse(scheme + "://" + host + path)
}

func uniqueHostURLs(seeds []string) []*url.URL {
	seen := map[string]struct{}{}
	var out []*url.URL
	for _, s := range seeds {
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil || u.Host == "" {
			continue
		}
		key := u.Scheme + "://" + u.Host
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"})
	}
	return out
}
