package fingerprint

import (
	"regexp"
	"strings"
)

// headerRule matches when the named response header contains needle
// (case-insensitive substring). An empty needle means "any non-empty
// value matches". set populates the matching identifier fields on the
// Stack; the rule's name reads back through label().
//
// When verField is non-empty, the first dotted-decimal version found in
// the header value is stored in Stack.Versions under that key. Rules
// for headers that don't carry a version (CF-Ray, X-Sucuri-ID, etc.)
// leave verField empty.
type headerRule struct {
	header   string
	needle   string
	set      func(*Stack)
	verField string
}

// versionPattern matches the first dotted-decimal number in a string,
// e.g. "1.25.0" in "nginx/1.25.0 (Ubuntu)" or "4.0.30319" alone. The
// minimum of one dot rules out opaque single integers (build IDs, byte
// counts, X-Runtime seconds-as-decimal-without-dot, etc.).
var versionPattern = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)+`)

func setVersion(s *Stack, field, value string) {
	if s.Versions == nil {
		s.Versions = map[string]string{}
	}
	s.Versions[field] = value
}

func (r headerRule) label() string {
	if r.needle != "" {
		return r.needle
	}
	return r.header
}

// Order matters loosely: later rules may overwrite earlier ones for the
// same field. We put broad matches first (e.g. Server=nginx) and more
// specific matches after (e.g. Server=openresty implies nginx-derived,
// but is reported as openresty).
var headerRules = []headerRule{
	// --- Server / language hints from Server header ---
	{header: "Server", needle: "nginx", verField: "server", set: func(s *Stack) { s.Server = "nginx" }},
	{header: "Server", needle: "openresty", verField: "server", set: func(s *Stack) { s.Server = "openresty" }},
	{header: "Server", needle: "apache", verField: "server", set: func(s *Stack) { s.Server = "apache" }},
	{header: "Server", needle: "caddy", verField: "server", set: func(s *Stack) { s.Server = "caddy" }},
	{header: "Server", needle: "litespeed", verField: "server", set: func(s *Stack) { s.Server = "litespeed" }},
	{header: "Server", needle: "microsoft-iis", verField: "server", set: func(s *Stack) {
		s.Server = "iis"
		s.Language = "dotnet"
	}},
	{header: "Server", needle: "cloudflare", set: func(s *Stack) {
		s.CDN = "cloudflare"
		s.WAF = "cloudflare"
	}},
	{header: "Server", needle: "akamaighost", set: func(s *Stack) { s.CDN = "akamai" }},
	{header: "Server", needle: "ecs", set: func(s *Stack) { s.CDN = "edgecast" }},

	// --- Language hints from X-Powered-By ---
	{header: "X-Powered-By", needle: "php", verField: "language", set: func(s *Stack) { s.Language = "php" }},
	{header: "X-Powered-By", needle: "asp.net", verField: "framework", set: func(s *Stack) {
		s.Language = "dotnet"
		s.Framework = "asp.net"
	}},
	{header: "X-Powered-By", needle: "express", verField: "framework", set: func(s *Stack) {
		s.Language = "node"
		s.Framework = "express"
	}},
	{header: "X-Powered-By", needle: "next.js", verField: "framework", set: func(s *Stack) {
		s.Language = "node"
		s.Framework = "nextjs"
	}},
	{header: "X-Powered-By", needle: "nuxt", verField: "framework", set: func(s *Stack) {
		s.Language = "node"
		s.Framework = "nuxt"
	}},
	{header: "X-Powered-By", needle: "servlet", set: func(s *Stack) { s.Language = "java" }},
	{header: "X-Powered-By", needle: "django", verField: "framework", set: func(s *Stack) {
		s.Language = "python"
		s.Framework = "django"
	}},

	// --- Framework / runtime hints ---
	{header: "X-AspNet-Version", verField: "framework", set: func(s *Stack) {
		s.Language = "dotnet"
		s.Framework = "asp.net"
	}},
	{header: "X-AspNetMvc-Version", verField: "framework", set: func(s *Stack) {
		s.Language = "dotnet"
		s.Framework = "asp.net-mvc"
	}},
	{header: "X-Runtime", set: func(s *Stack) {
		// X-Runtime is emitted by Rails and a few others; only set if we
		// haven't already pinned a language.
		if s.Language == "" {
			s.Language = "ruby"
		}
		if s.Framework == "" {
			s.Framework = "rails"
		}
	}},
	{header: "X-Rack-Cache", set: func(s *Stack) {
		s.Language = "ruby"
		s.Framework = "rails"
	}},
	{header: "X-Drupal-Cache", set: func(s *Stack) {
		s.CMS = "drupal"
		s.Language = "php"
	}},
	{header: "X-Generator", needle: "drupal", set: func(s *Stack) {
		s.CMS = "drupal"
		s.Language = "php"
	}},

	// --- CDN / WAF ---
	{header: "CF-Ray", set: func(s *Stack) {
		s.CDN = "cloudflare"
		if s.WAF == "" {
			s.WAF = "cloudflare"
		}
	}},
	{header: "CF-Cache-Status", set: func(s *Stack) { s.CDN = "cloudflare" }},
	{header: "X-Sucuri-ID", set: func(s *Stack) { s.WAF = "sucuri" }},
	{header: "X-Sucuri-Cache", set: func(s *Stack) { s.WAF = "sucuri" }},
	{header: "X-Iinfo", set: func(s *Stack) { s.WAF = "incapsula" }},
	{header: "X-CDN", needle: "incapsula", set: func(s *Stack) { s.WAF = "incapsula" }},
	{header: "X-Amz-Cf-Id", set: func(s *Stack) { s.CDN = "cloudfront" }},
	{header: "Via", needle: "cloudfront", set: func(s *Stack) { s.CDN = "cloudfront" }},
	{header: "X-Served-By", needle: "cache-", set: func(s *Stack) { s.CDN = "fastly" }},
	{header: "X-Fastly-Request-ID", set: func(s *Stack) { s.CDN = "fastly" }},
	{header: "X-Akamai-Transformed", set: func(s *Stack) { s.CDN = "akamai" }},
	{header: "X-Amzn-Trace-Id", set: func(s *Stack) {
		if s.CDN == "" {
			s.CDN = "aws"
		}
	}},
}

// cookieRule matches a Set-Cookie by exact name (case-insensitive) or by
// prefix when name ends with "*".
type cookieRule struct {
	name string
	set  func(*Stack)
}

func (r cookieRule) match(lowerName string) bool {
	want := strings.ToLower(r.name)
	if strings.HasSuffix(want, "*") {
		return strings.HasPrefix(lowerName, strings.TrimSuffix(want, "*"))
	}
	return lowerName == want
}

var cookieRules = []cookieRule{
	{name: "PHPSESSID", set: func(s *Stack) { s.Language = "php" }},
	{name: "JSESSIONID", set: func(s *Stack) { s.Language = "java" }},
	{name: "ASP.NET_SessionId", set: func(s *Stack) { s.Language = "dotnet" }},
	{name: "ASPSESSIONID*", set: func(s *Stack) { s.Language = "dotnet" }},
	{name: "laravel_session", set: func(s *Stack) {
		s.Language = "php"
		s.Framework = "laravel"
	}},
	{name: "XSRF-TOKEN", set: func(s *Stack) {
		// Used by Laravel, Angular, AdonisJS, others. Only a hint - don't
		// pin a framework on this alone; we just record the signal.
	}},
	{name: "ci_session", set: func(s *Stack) {
		s.Language = "php"
		s.Framework = "codeigniter"
	}},
	{name: "_rails_session", set: func(s *Stack) {
		s.Language = "ruby"
		s.Framework = "rails"
	}},
	{name: "_session_id", set: func(s *Stack) {
		// Rails default; weaker signal than _rails_session.
		if s.Framework == "" {
			s.Framework = "rails"
			s.Language = "ruby"
		}
	}},
	{name: "connect.sid", set: func(s *Stack) {
		s.Language = "node"
		s.Framework = "express"
	}},
	{name: "sessionid", set: func(s *Stack) {
		// Django's default; weaker than seeing the framework header.
		if s.Framework == "" {
			s.Language = "python"
			s.Framework = "django"
		}
	}},
	{name: "wordpress_logged_in_*", set: func(s *Stack) {
		s.CMS = "wordpress"
		s.Language = "php"
	}},
	{name: "wp-settings-*", set: func(s *Stack) {
		s.CMS = "wordpress"
		s.Language = "php"
	}},
	{name: "MoodleSession", set: func(s *Stack) {
		s.CMS = "moodle"
		s.Language = "php"
	}},
}

// bodyRule matches against the HTML body (bounded by maxBodyBytes).
// label is the short identifier used in Signals. When verField is set,
// the first capture group in re (if non-empty) is stored as the version
// for that Stack.Versions key.
type bodyRule struct {
	label    string
	re       *regexp.Regexp
	set      func(*Stack)
	verField string
}

var bodyRules = []bodyRule{
	{
		label:    "meta-generator:wordpress",
		re:       regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress(?:\s+([0-9][0-9.]*))?`),
		verField: "cms",
		set: func(s *Stack) {
			s.CMS = "wordpress"
			s.Language = "php"
		},
	},
	{
		label:    "meta-generator:drupal",
		re:       regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']Drupal(?:\s+([0-9][0-9.]*))?`),
		verField: "cms",
		set: func(s *Stack) {
			s.CMS = "drupal"
			s.Language = "php"
		},
	},
	{
		label:    "meta-generator:joomla",
		re:       regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']Joomla(?:[!\s]+([0-9][0-9.]*))?`),
		verField: "cms",
		set: func(s *Stack) {
			s.CMS = "joomla"
			s.Language = "php"
		},
	},
	{
		label:    "meta-generator:ghost",
		re:       regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']Ghost(?:\s+([0-9][0-9.]*))?`),
		verField: "cms",
		set: func(s *Stack) {
			s.CMS = "ghost"
			s.Language = "node"
		},
	},
	{
		label:    "meta-generator:magento",
		re:       regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']Magento(?:\s+([0-9][0-9.]*))?`),
		verField: "cms",
		set: func(s *Stack) {
			s.CMS = "magento"
			s.Language = "php"
		},
	},
	{
		label: "wp-content-path",
		re:    regexp.MustCompile(`/wp-(?:admin|content|includes)/`),
		set: func(s *Stack) {
			s.CMS = "wordpress"
			s.Language = "php"
		},
	},
	{
		label: "next-data",
		re:    regexp.MustCompile(`__NEXT_DATA__`),
		set: func(s *Stack) {
			s.Language = "node"
			s.Framework = "nextjs"
		},
	},
	{
		label: "nuxt-data",
		re:    regexp.MustCompile(`__NUXT__`),
		set: func(s *Stack) {
			s.Language = "node"
			s.Framework = "nuxt"
		},
	},
	{
		label: "csrf-meta",
		re:    regexp.MustCompile(`(?i)<meta\s+name=["']csrf-token["']`),
		// Both Rails and Laravel emit csrf-token meta. Only weakly hint at
		// "framework with CSRF protection" - don't overwrite a real match.
		set: func(s *Stack) {},
	},
}
