-- security-headers: flags HTML responses that omit one or more of the
-- five canonical response-side security headers (CSP, HSTS,
-- X-Content-Type-Options, X-Frame-Options, Referrer-Policy). Every
-- missing header on the same page collapses into a single finding
-- with one bullet per header so the report carries one configuration
-- defect with several facets rather than five near-duplicate rows.

local check = {
  name  = "security-headers",
  level = "passive",
  scope = "host",
  owasp = "A05:2021 Security Misconfiguration",
  tier  = "passive",
}

local SEVERITY_RANK = { info = 0, low = 1, medium = 2, high = 3, critical = 4 }

local HEADER_RULES = {
  ["Content-Security-Policy"] = {
    severity    = "medium",
    cwe         = "CWE-693",
    remediation = "Set Content-Security-Policy with a restrictive default-src and explicit allowlists for script-src, style-src, and frame-ancestors. Start in Report-Only mode if needed.",
  },
  ["Strict-Transport-Security"] = {
    severity    = "medium",
    cwe         = "CWE-319",
    remediation = "Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload over HTTPS. Confirm all subdomains serve HTTPS before enabling includeSubDomains.",
  },
  ["X-Content-Type-Options"] = {
    severity    = "low",
    cwe         = "CWE-693",
    remediation = "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
  },
  ["X-Frame-Options"] = {
    severity    = "low",
    cwe         = "CWE-1021",
    remediation = "Set X-Frame-Options: DENY (or SAMEORIGIN) and/or Content-Security-Policy: frame-ancestors 'none' to mitigate clickjacking.",
  },
  ["Referrer-Policy"] = {
    severity    = "low",
    cwe         = "CWE-200",
    remediation = "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for higher-sensitivity properties).",
  },
}

-- Sorted iteration order keeps the resulting `missing` list and any
-- composite text deterministic across runs.
local HEADER_NAMES = {
  "Content-Security-Policy",
  "Referrer-Policy",
  "Strict-Transport-Security",
  "X-Content-Type-Options",
  "X-Frame-Options",
}

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  -- CSP / XFO / Referrer-Policy govern browser HTML rendering. Flagging
  -- them missing on a JSON API, an image, or a 404 page is noise; limit
  -- to 200 OK HTML responses so the finding tracks real attack surface.
  if snap.status ~= 200 then return nil end
  if not ctx.body.is_html_ct(snap.headers:get("Content-Type")) then
    return nil
  end

  local missing = {}
  for _, h in ipairs(HEADER_NAMES) do
    if snap.headers:get(h) == "" then
      missing[#missing + 1] = h
    end
  end
  if #missing == 0 then return nil end

  local max_sev = "info"
  local seen_cwe = {}
  local cwes = {}
  local details = {}
  for _, h in ipairs(missing) do
    local rule = HEADER_RULES[h]
    if SEVERITY_RANK[rule.severity] > SEVERITY_RANK[max_sev] then
      max_sev = rule.severity
    end
    if not seen_cwe[rule.cwe] then
      seen_cwe[rule.cwe] = true
      cwes[#cwes + 1] = rule.cwe
    end
    details[#details + 1] = h .. ": " .. rule.remediation
  end

  local title
  if #missing == 1 then
    title = "missing security header: " .. missing[1]
  else
    title = string.format("missing %d security headers", #missing)
  end

  return {{
    severity = ctx.severity[max_sev],
    title    = title,
    detail   = "response from " .. ctx.page.url .. " did not include the following security headers",
    details  = details,
    cwe      = table.concat(cwes, ", "),
    evidence = ctx.evidence.build {
      method  = "GET",
      url     = ctx.page.url,
      status  = snap.status,
      headers = snap.headers,
    },
    -- Single per-host finding: missing headers on example.com is one
    -- site-wide config issue, not one per crawled page.
    dedupe_parts = { "missing-headers" },
  }}
end

return check
