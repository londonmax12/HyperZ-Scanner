package checks

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// CacheControlSensitive detects HTML responses that may contain sensitive
// information but lack cache directives (private, no-store, no-cache) that
// prevent storage in shared caches or browser history. Uncontrolled caching
// of authenticated pages, forms, or API responses can leak data to other users,
// proxy operators, or attackers with local access to the browser cache.
type CacheControlSensitive struct{}

func (CacheControlSensitive) Name() string { return "cache-control-sensitive" }

func (CacheControlSensitive) Level() Level { return LevelPassive }

func (c CacheControlSensitive) Run(ctx context.Context, client *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	snap, err := ensureResponse(ctx, client, p, 0)
	if err != nil {
		return nil, err
	}
	// Only check HTML responses; cache control for images, scripts, etc.
	// is less critical from a data-leakage standpoint.
	if !isHTMLContentType(snap.Headers.Get("Content-Type")) {
		return nil, nil
	}

	cacheControl := snap.Headers.Get("Cache-Control")
	pragma := snap.Headers.Get("Pragma")
	expires := snap.Headers.Get("Expires")

	// Check if the response has appropriate cache-control directives.
	// Sensitive directives are: private, no-store, no-cache (at minimum).
	hasSafeDirective := false
	if cacheControl != "" {
		// Directives are comma-separated, may have values. Check for
		// substrings so "private, max-age=0" and "no-store" both match.
		directives := strings.ToLower(cacheControl)
		for _, safe := range []string{"private", "no-store", "no-cache"} {
			if strings.Contains(directives, safe) {
				hasSafeDirective = true
				break
			}
		}
	}

	// If no safe Cache-Control directive, check older alternatives.
	// Pragma: no-cache was the pre-HTTP/1.1 way to prevent caching.
	if !hasSafeDirective && strings.ToLower(pragma) == "no-cache" {
		hasSafeDirective = true
	}

	// Expires: 0 or past date disables caching; future date (without Cache-Control)
	// is problematic. We don't flag on Expires alone since it requires Date header
	// context to interpret, and our check is simple. If Cache-Control is missing
	// entirely and Expires is present, that's already flagged below.

	// If the response has no Cache-Control and no safe Pragma, it may be
	// cached by default per HTTP/1.1. This is risky for HTML that might
	// contain sensitive data (forms, auth pages, etc.).
	if hasSafeDirective {
		return nil, nil
	}

	// No safe cache directive found. Flag it.
	// HTML responses (especially 200 OK) should typically prevent caching
	// to avoid leaking authenticated content.
	detail := "Response includes HTML content but does not specify cache-control directives"
	if cacheControl == "" && pragma == "" {
		detail += " (Cache-Control and Pragma headers missing)"
	} else if cacheControl == "" {
		detail += fmt.Sprintf(" (Pragma: %q is insufficient for modern browsers)", pragma)
	} else {
		detail += fmt.Sprintf(" (Cache-Control: %q lacks private/no-store/no-cache)", cacheControl)
	}

	remediation := "Set Cache-Control: private, no-store, no-cache (or at minimum private) for authenticated or sensitive pages. " +
		"Use public, max-age=<seconds> only for cacheable, non-sensitive content. " +
		"For dynamic pages, prefer private to prevent caching in shared proxies."

	return []Finding{{
		Check:       c.Name(),
		Target:      p.URL,
		URL:         p.URL,
		Severity:    SeverityMedium,
		Title:       "HTML response lacks cache-control security directives",
		Detail:      detail,
		CWE:         "CWE-524",
		OWASP:       "A05:2021 Security Misconfiguration",
		Remediation: remediation,
		Evidence:    BuildEvidence("GET", p.URL, snap.Status, snap.Headers, ""),
		// Per-host: caching configuration is typically site-wide.
		DedupeKey: MakeKey(c.Name(), ScopeHost, p.URL, "no-safe-directives"),
	}}, nil
}
