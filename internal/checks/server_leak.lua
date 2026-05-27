-- server-leak: flags response headers that disclose server software
-- or runtime version. The leak itself is not a vulnerability, but it
-- narrows an attacker's search space (pairing "nginx/1.18.0" with a
-- public CVE list is a one-step lookup), so severity stays info.

local check = {
  name        = "server-leak",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-200",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = nil, -- per-finding because the header name is interpolated
}

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
        -- issue, but Server and X-Powered-By stay distinct so a
        -- multi-header response produces two findings.
        dedupe_parts = { "leak-header:" .. header },
      }
    end
  end
  return findings
end

return check
