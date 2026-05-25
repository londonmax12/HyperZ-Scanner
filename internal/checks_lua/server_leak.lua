-- server-leak: pilot Lua port of internal/checks/server_leak.go.
-- Flags response headers that disclose server software or runtime
-- version. The information itself is not a vulnerability but it
-- narrows an attacker's search space (pairing "nginx/1.18.0" with
-- a public CVE list is a one-step lookup). Severity stays info to
-- reflect that.
--
-- Behavior must stay identical to the Go check: same headers
-- inspected (Server, X-Powered-By), same dedupe scope (per host +
-- header name), same severity / cwe / owasp / remediation strings.
-- The Go version's tests double as a parity check for this port.

local check = {
  name        = "server-leak",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-200",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = nil, -- per-finding because the header name is interpolated
}

-- Closed set of headers we report. CWE-200 / OWASP A05:2021 apply
-- to both. Order matches the Go check's sort.Strings output so the
-- multi-header response produces identical finding order.
local LEAK_HEADERS = { "Server", "X-Powered-By" }

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  local evidence = ctx.evidence.build {
    method  = "GET",
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }

  local findings = {}
  for _, header in ipairs(LEAK_HEADERS) do
    local value = snap.headers:get(header)
    if value ~= "" then
      findings[#findings + 1] = {
        severity    = ctx.severity.info,
        title       = "server software disclosed via " .. header,
        detail      = ctx.page.url .. " responded with " .. header .. ": " .. value,
        remediation = "Suppress or generalize the " .. header
                      .. " header at the server/proxy layer so version details aren't advertised.",
        evidence    = evidence,
        -- Per-host + header: same leak across crawled pages is one
        -- issue. Header name in the key keeps Server and X-Powered-By
        -- distinct so a multi-header response produces two findings,
        -- matching the Go check 1:1.
        dedupe_parts = { "leak-header:" .. header },
      }
    end
  end
  return findings
end

return check
