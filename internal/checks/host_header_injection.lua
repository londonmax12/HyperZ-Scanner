-- host-header-injection: Lua port of
-- internal/checks/host_header_injection.go.
--
-- Probes whether the Host header is reflected in the response body
-- or used to generate absolute URLs. A reflected Host is the root
-- primitive behind cache poisoning, password reset link hijacking,
-- and host-routing-based SSRF.
--
-- One canary probe per page: GET the page URL with Host overridden
-- to a reserved (.example) host and search the response body for any
-- occurrence of the canary string. RFC 2606 guarantees the canary
-- domain is unregistered so a body hit is confirmed reflection, not
-- coincidence.

local check = {
  name        = "host-header-injection",
  level       = "default",
  scope       = "host",
  cwe         = "CWE-74",
  owasp       = "A06:2021 Vulnerable and Outdated Components",
  remediation = "Whitelist the allowed Host header values and validate incoming Host headers against this list. "
                .. "Use absolute URLs from configuration (not derived from the Host header) for sensitive operations like password resets. "
                .. "Implement cache-busting strategies per Host header variant, or use Host-independent cache keys. "
                .. "Use HTTP/2 or enforce Host header validation at the proxy layer.",
}

local CANARY    = "evil.example"
local BODY_CAP  = 8 * 1024

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then
    return nil
  end
  -- Non-passive checks must consult scope before probing.
  if not ctx.scope:allows(ctx.page.url) then
    return nil
  end

  local req, nerr = ctx.client:new_request {
    method  = "GET",
    url     = ctx.page.url,
    host    = CANARY,
    headers = { Host = CANARY },
  }
  if nerr then
    ctx:report("host header build req: " .. nerr)
    return nil
  end

  -- `do` is a Lua keyword so the method is registered under the
  -- string "do" but cannot be called with method syntax. Bracket
  -- access dispatches to the same binding with the explicit receiver.
  local resp, derr = ctx.client["do"](ctx.client, req)
  if derr then
    ctx:report("host header probe: " .. derr)
    return nil
  end

  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then
    ctx:report("host header read body: " .. rerr)
    return nil
  end

  if not string.find(string.lower(body), string.lower(CANARY), 1, true) then
    return nil
  end

  return {{
    severity = ctx.severity.high,
    title    = "Host header reflected in response",
    detail   = string.format(
      "The Host header is reflected unsafely in the response body. "
        .. "When probed with Host: %s, the response contained the injected host value. "
        .. "This can lead to cache poisoning, password reset link hijacking, SSRF via routing, and authentication bypass. "
        .. "An attacker can control the Host header in HTTP/1.1 requests to inject content into cache entries or response-generation logic.",
      CANARY),
    evidence = ctx.evidence.from_exchange {
      request   = req,
      response  = resp,
      body      = body,
      truncated = truncated,
    },
    -- Per-host: same bug at every crawled page is one finding.
    dedupe_parts = {},
  }}
end

return check
