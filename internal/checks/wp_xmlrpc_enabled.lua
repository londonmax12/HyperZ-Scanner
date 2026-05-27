-- wp-xmlrpc-enabled: flags WordPress installs whose /xmlrpc.php
-- endpoint accepts and answers anonymous XML-RPC requests. WordPress
-- ships /xmlrpc.php enabled by default; operators that do not need
-- the legacy XML-RPC protocol (Jetpack, mobile-app integrations, the
-- old WordPress mobile API) should disable it to reduce attack
-- surface.
--
-- Why it matters:
--
--   * Credential brute-force amplification: wp.getUsersBlogs accepts
--     a username/password pair per call, and system.multicall lets
--     an attacker batch dozens of attempts into one HTTP request,
--     bypassing per-request rate-limits.
--   * Pingback SSRF: the pingback.ping method makes the server
--     issue an outbound HTTP fetch to an attacker-supplied URL,
--     which has been used to scan internal networks and amplify
--     DDoS attacks.
--   * Information disclosure: system.listMethods returns the full
--     RPC API the server exposes, which an attacker uses to plan
--     more targeted abuse.
--
-- The check confirms the endpoint by POSTing a system.listMethods
-- request and looking for the canonical <methodResponse>...
-- pingback.ping</methodResponse> shape in the body. A page that
-- happens to return 200 for /xmlrpc.php without speaking XML-RPC
-- (e.g. a static catch-all) does not match.
--
-- applies_to gates to detected WordPress hosts so the probe does not
-- waste a request on non-WP targets. The check claims the host root
-- via ctx.host.claim_once so a crawl of many pages on one site
-- triggers exactly one POST to /xmlrpc.php.

local check = {
  name        = "wp-xmlrpc-enabled",
  level       = "default",
  scope       = "host",
  cwe         = "CWE-200",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Disable /xmlrpc.php at the web server or via a security plugin (e.g. WordPress filter `xmlrpc_enabled = false` or a server-level deny). If XML-RPC is required for a specific integration, restrict it to the integration's source IPs. Even when kept, disable pingback.ping (which is the SSRF / DDoS amplification vector) via the `xmlrpc_methods` filter.",
  tier        = "passive",
  applies_to  = { cms = {"wordpress"} },
}

local BODY_CAP = 16 * 1024

local LIST_METHODS_BODY = [[<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params/>
</methodCall>]]

-- xmlrpc_response_shape reports whether body looks like a genuine
-- XML-RPC methodResponse. A loose match - the canonical envelope
-- always contains <methodResponse> and at least one <string> entry
-- in the params array, so requiring both rejects a stray
-- "methodResponse" word inside an HTML page.
local function xmlrpc_response_shape(body)
  if body == nil or body == "" then return false end
  if body:find("<methodResponse", 1, true) == nil then return false end
  -- params/value/array/data with a <string> inside is the standard
  -- shape for system.listMethods. A site that catches the request
  -- but does not actually run an RPC dispatcher would return a
  -- different shape (an HTML 404 with no <string> entries).
  return body:find("<string>", 1, true) ~= nil
end

-- has_pingback returns true when the listMethods response advertises
-- the pingback.ping method - the SSRF / amplification surface that
-- operators most often want to know about.
local function has_pingback(body)
  return body ~= nil and body:find("pingback.ping", 1, true) ~= nil
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  local host_root = u.scheme .. "://" .. u.host
  if not ctx.scope:allows(host_root) then return nil end
  if not ctx.host.claim_once(host_root) then return nil end

  local probe_url = host_root .. "/xmlrpc.php"

  local req, mut_err = ctx.client:new_request{
    method  = "POST",
    url     = probe_url,
    body    = LIST_METHODS_BODY,
    headers = { ["Content-Type"] = "text/xml" },
  }
  if mut_err then return nil, "wp-xmlrpc-enabled: " .. mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, "wp-xmlrpc-enabled: " .. do_err end

  if resp:status() ~= 200 then return nil end

  local body, _, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, "wp-xmlrpc-enabled: " .. rerr end

  if not xmlrpc_response_shape(body) then return nil end

  local detail_tail = ""
  if has_pingback(body) then
    detail_tail = " The response advertises pingback.ping; an attacker can use this method to issue server-side HTTP requests to internal hosts (blind SSRF) or to amplify DDoS attacks against third-party URLs."
  end

  return {
    {
      severity    = ctx.severity.medium,
      target      = host_root,
      url         = probe_url,
      title       = "WordPress XML-RPC endpoint accepts anonymous requests",
      detail      = string.format(
        "POST %s with a system.listMethods envelope returned a valid XML-RPC methodResponse, confirming /xmlrpc.php is enabled. The endpoint amplifies credential brute-force attempts via system.multicall and exposes server-side request methods that operators often do not need on a default install.%s",
        probe_url, detail_tail),
      evidence = ctx.evidence.build{
        method  = "POST",
        url     = probe_url,
        status  = resp:status(),
        headers = resp:headers(),
        body    = body,
      },
      dedupe_parts = { "wp-xmlrpc-enabled" },
    },
  }
end

return check
