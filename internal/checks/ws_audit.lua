-- ws-audit: probes WebSocket endpoints discovered on a crawled page
-- for two defects:
--
--  1. Cross-Site WebSocket Hijacking (CSWSH): the endpoint accepts a
--     real RFC 6455 handshake when the request carries a foreign
--     Origin. WebSockets are NOT subject to the browser's same-origin
--     policy at the network layer; server-side Origin validation is
--     the only thing standing between a victim's authenticated
--     session and an attacker-controlled page opening the same socket
--     and replaying the victim's cookies. Confirmation requires both
--     101 Switching Protocols AND a valid Sec-WebSocket-Accept (the
--     bridge enforces both), so a proxy returning 101 for arbitrary
--     upgrades does not false-positive.
--
--  2. Cleartext WebSocket on HTTPS: an https:// page advertises a
--     ws:// endpoint. Browsers block the load as mixed active content,
--     but the reference itself reveals the channel and anyone on the
--     network path can read or tamper every frame. Fires on cross-host
--     references too because the privacy / integrity hit lands on the
--     user regardless of who owns the WS server.
--
-- The check fires at LevelDefault. Dedupe is composed explicitly per
-- finding via ctx.dedupe.key so the CSWSH arm keys off the endpoint
-- URL (one channel-level issue across all crawl entry points) while
-- the finding's Target field stays the page URL (for reporting).

local check = {
  name  = "ws-audit",
  level = "default",
  scope = "host",
}

function check.run(ctx)
  local target = ctx.page.url
  local page_url, perr = ctx.url.parse(target)
  if perr or not page_url or page_url.host == "" then return nil end
  if not ctx.scope:allows(target) then return nil end

  local endpoints = ctx.ws.discover_endpoints(ctx.page.body)
  if #endpoints == 0 then return nil end

  local origin = ctx.ws.foreign_origin()
  local probe_cap = ctx.ws.max_endpoints_per_page()
  -- Probe eligibility: hard-gate on scope, then admit exact-host
  -- endpoints, anything the operator pinned via scope hosts, or in
  -- the wide-open scope case fall back to same-registrable-domain
  -- (eTLD+1). Real apps almost always offload WebSockets to a
  -- dedicated subdomain (ws.target.com from app.target.com), so
  -- exact-hostname matching was missing the common architecture; the
  -- eTLD+1 fallback keeps open-scope runs from probing arbitrary
  -- third-party ws:// references found in body content.
  local scope_pinned = ctx.scope:has_hosts()
  local findings = {}
  local probed = 0

  for _, ep in ipairs(endpoints) do
    local ep_url, eperr = ctx.url.parse(ep)
    if not eperr and ep_url and ep_url.host ~= "" then

      -- Cleartext-on-HTTPS: an https:// page advertises a ws:// (no
      -- TLS) endpoint. Fires regardless of host because the user is
      -- the one who eats the privacy/integrity hit on the wire.
      if string.lower(ep_url.scheme) == "ws"
          and string.lower(page_url.scheme) == "https" then
        findings[#findings + 1] = {
          target      = target,
          url         = target,
          severity    = ctx.severity.medium,
          title       = "HTTPS page references cleartext WebSocket " .. ep,
          detail      = "An https:// page advertises a ws:// WebSocket endpoint. Modern browsers block the connection "
              .. "as mixed active content, but the reference itself reveals the channel to anyone reading the page "
              .. "source. Anyone who can sit on the network path between the client and that endpoint can read or "
              .. "tamper with every frame in both directions because the channel is unencrypted.",
          cwe         = "CWE-319",
          owasp       = "A02:2021 Cryptographic Failures",
          remediation = "Serve the WebSocket over wss:// (TLS) and update every page reference. If the WebSocket "
              .. "server is behind a load balancer or reverse proxy, terminate TLS there and forward the upgraded "
              .. "connection as plaintext on the trusted internal segment.",
          evidence    = ctx.evidence.build {
            method  = "GET",
            url     = ep,
            snippet = "Page " .. target .. " references " .. ep,
          },
          dedupe_parts = { "cleartext:" .. ep },
        }
      end

      -- Same-organization filter: trust scope when the operator
      -- pinned an allowlist, otherwise fall back to eTLD+1. Scope is
      -- re-checked here so a same-host endpoint outside the operator's
      -- scope (e.g. port-restricted) is not probed.
      local same_host = string.lower(ep_url.hostname) == string.lower(page_url.hostname)
      local eligible = same_host or scope_pinned
          or ctx.url.same_site(ep_url.hostname, page_url.hostname)
      if eligible and ctx.scope:allows(ep) and probed < probe_cap then
        probed = probed + 1
        local res, herr = ctx.ws.handshake { url = ep, origin = origin }
        if herr then
          ctx:report("ws-audit handshake " .. ep .. ": " .. herr)
        elseif res.accepted then
          findings[#findings + 1] = {
            target      = target,
            url         = ep,
            severity    = ctx.severity.high,
            title       = "WebSocket handshake accepted from foreign Origin",
            detail      = "The endpoint completed an RFC 6455 handshake when the request carried Origin: " .. origin
                .. ". WebSocket connections are NOT subject to the same-origin policy at the browser level; the only "
                .. "thing standing between a victim's authenticated session and an attacker-controlled page is server-side "
                .. "Origin validation. With validation absent, any web page the victim visits can open a socket to this "
                .. "endpoint, replay the victim's session cookies, and read or send messages on the channel. This is the "
                .. "WebSocket analogue of cross-site request forgery (Cross-Site WebSocket Hijacking / CSWSH).",
            cwe         = "CWE-346",
            owasp       = "A01:2021 Broken Access Control",
            remediation = "Validate the request's Origin header against an allowlist of trusted origins during the "
                .. "WebSocket handshake (HTTP 403 on mismatch). For session-bound channels, additionally require a "
                .. "non-cookie credential (signed token in a sub-protocol or in the first message); cookies alone are "
                .. "vulnerable to replay from any origin the user happens to visit.",
            evidence    = ctx.evidence.build {
              method  = "GET",
              url     = ep,
              status  = res.status,
              snippet = res.snippet,
            },
            -- Channel-scoped dedupe: the same vulnerable endpoint
            -- referenced from N crawl entry points is one issue. Key
            -- explicitly off the endpoint URL so the page URL on
            -- Finding.Target (used for report display) is unaffected.
            dedupe_key = ctx.dedupe.key {
              check  = check.name,
              scope  = "page",
              target = ep,
              parts  = { "cswsh" },
            },
          }
        end
      end
    end
  end
  return findings
end

return check
