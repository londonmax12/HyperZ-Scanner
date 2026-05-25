-- cache-control-sensitive: Lua port of
-- internal/checks/cache_control_sensitive.go.
--
-- Flags HTML responses that lack a cache-control directive
-- (private / no-store / no-cache) that would prevent storage in
-- shared caches or browser history. Sensitive data leaks via cached
-- copies are silent and persistent, so the check is conservative -
-- only HTML responses are inspected, and a single host-wide finding
-- is emitted rather than one per crawled page.
--
-- Parity oracle: internal/checks/cache_control_sensitive_test.go.

local check = {
  name        = "cache-control-sensitive",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-524",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Set Cache-Control: private, no-store, no-cache (or at minimum private) for authenticated or sensitive pages. "
                .. "Use public, max-age=<seconds> only for cacheable, non-sensitive content. "
                .. "For dynamic pages, prefer private to prevent caching in shared proxies.",
}

local SAFE_DIRECTIVES = { "private", "no-store", "no-cache" }

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end
  if not ctx.body.is_html_ct(snap.headers:get("Content-Type")) then
    return nil
  end

  local cache_control = snap.headers:get("Cache-Control")
  local pragma        = snap.headers:get("Pragma")

  -- Substring match on the lower-cased value so directives that ride
  -- alongside max-age (e.g. "private, max-age=0") still register.
  local cc_lower = string.lower(cache_control)
  for _, safe in ipairs(SAFE_DIRECTIVES) do
    if string.find(cc_lower, safe, 1, true) then
      return nil
    end
  end
  -- Older Pragma: no-cache equivalent. Pre-HTTP/1.1 path; kept for
  -- compatibility with the Go check's accepted-set.
  if string.lower(pragma) == "no-cache" then
    return nil
  end

  local detail = "Response includes HTML content but does not specify cache-control directives"
  if cache_control == "" and pragma == "" then
    detail = detail .. " (Cache-Control and Pragma headers missing)"
  elseif cache_control == "" then
    detail = detail .. string.format(' (Pragma: "%s" is insufficient for modern browsers)', pragma)
  else
    detail = detail .. string.format(' (Cache-Control: "%s" lacks private/no-store/no-cache)', cache_control)
  end

  return {{
    severity = ctx.severity.medium,
    title    = "HTML response lacks cache-control security directives",
    detail   = detail,
    evidence = ctx.evidence.build {
      method  = "GET",
      url     = ctx.page.url,
      status  = snap.status,
      headers = snap.headers,
    },
    -- Per-host: caching configuration is typically site-wide; the
    -- same defect on every crawled page is one report row.
    dedupe_parts = { "no-safe-directives" },
  }}
end

return check
