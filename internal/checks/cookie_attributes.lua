-- cookie-attributes: Lua port of internal/checks/cookie_attributes.go.
--
-- Parses Set-Cookie headers and emits one finding per (cookie,
-- missing attribute). Severity is fixed per attribute; the cookie
-- name + attribute are stamped into the per-finding dedupe parts so
-- two cookies missing the same flag are two findings and the same
-- cookie missing two flags is two findings.
--
-- Set-Cookie parsing delegates to ctx.cookies.from_headers, which
-- wraps net/http's parser - matches the Go check's parse rules
-- 1:1 (including Lax/Strict/None canonicalization and "default ==
-- absent" treatment).

local check = {
  name  = "cookie-attributes",
  level = "passive",
  scope = "host",
  owasp = "A05:2021 Security Misconfiguration",
}

-- attr_rules carries the per-attribute (severity, cwe, remediation)
-- triple. All three share OWASP A05:2021; per-finding cwe and
-- remediation are stamped here so the Go-original and the Lua port
-- emit identical metadata.
local ATTR_RULES = {
  Secure = {
    severity = "medium",
    cwe      = "CWE-614",
    remediation = "Add the Secure attribute so the cookie is only sent over HTTPS. SameSite=None additionally requires Secure to be set.",
  },
  HttpOnly = {
    severity = "low",
    cwe      = "CWE-1004",
    remediation = "Add HttpOnly so the cookie is not accessible via document.cookie, reducing the impact of XSS-driven session theft.",
  },
  SameSite = {
    severity = "low",
    cwe      = "CWE-1275",
    remediation = "Set SameSite=Lax (or Strict for session cookies). Use SameSite=None; Secure only for cross-site contexts.",
  },
}

local function build_finding(ctx, cookie_name, attr, evidence)
  local rule = ATTR_RULES[attr]
  return {
    severity    = ctx.severity[rule.severity],
    title       = string.format('cookie "%s" missing %s attribute', cookie_name, attr),
    detail      = string.format('Set-Cookie for "%s" at %s did not include %s', cookie_name, ctx.page.url, attr),
    cwe         = rule.cwe,
    remediation = rule.remediation,
    evidence    = evidence,
    -- Per-host + cookie + attribute: same cookie missing the same
    -- flag on every crawled page is one issue; different cookies or
    -- attributes get distinct keys.
    dedupe_parts = { "cookie:" .. cookie_name, "attr:" .. attr },
  }
end

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  local is_https = string.sub(string.lower(ctx.page.url), 1, 8) == "https://"
  local evidence = ctx.evidence.build {
    method  = "GET",
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }
  local cookies = ctx.cookies.from_headers(snap.headers)

  -- Stable order: Go sorts by name before emitting, so the parity
  -- test sees findings in the same sequence the Go check produces.
  table.sort(cookies, function(a, b) return a.name < b.name end)

  local findings = {}
  for _, ck in ipairs(cookies) do
    -- Secure only meaningful over HTTPS; on http:// the Set-Cookie
    -- can't be "fixed" without moving the host to HTTPS, so skip the
    -- flag - the broader HSTS / missing-header finding covers it.
    if not ck.secure and is_https then
      findings[#findings + 1] = build_finding(ctx, ck.name, "Secure", evidence)
    end
    if not ck.http_only then
      findings[#findings + 1] = build_finding(ctx, ck.name, "HttpOnly", evidence)
    end
    -- Lax/Strict/None are the explicit declarations of intent. The
    -- empty same_site string covers both "attribute absent" and
    -- "default mode" - both cases pick the browser implicit, which
    -- is what we want to surface.
    if ck.same_site ~= "lax" and ck.same_site ~= "strict" and ck.same_site ~= "none" then
      findings[#findings + 1] = build_finding(ctx, ck.name, "SameSite", evidence)
    end
  end
  return findings
end

return check
