-- sse-audit: probes Server-Sent Events (text/event-stream) endpoints for cross-
-- origin disclosure. SSE is a long-lived GET that browsers expose to
-- JS via EventSource and which is subject to CORS, so an endpoint
-- that returns ACAO: * (or echoes a foreign Origin alongside
-- credentials) leaks every event in the stream to any web page the
-- victim visits.
--
-- Discovery: two tracks. (1) Self-evidence - the already-fetched page
-- response is itself an SSE stream. (2) Body refs - the page body
-- contains `new EventSource(...)` literals whose URL argument we
-- extract. Bare-variable arguments are out of scope for a passive
-- body scan.
--
-- Per endpoint: at most one probe GET with a foreign Origin. The
-- probe uses a short read (4 KiB cap) so a real event stream does
-- not stall the worker.

local check = {
  name        = "sse-audit",
  level       = levels.default,
  scope       = scopes.page,
  cwe         = "CWE-942",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Validate the request Origin against a hardcoded allowlist before echoing it into "
                .. "Access-Control-Allow-Origin. SSE has no built-in same-origin protection; the only thing "
                .. "keeping a foreign page from reading the stream via EventSource is server-side CORS. If "
                .. "the stream MUST be public, remove credentials from the channel (sessionless tokens in the "
                .. "URL or first message) so a permissive ACAO does not leak authenticated content.",
  tier        = tiers.active,
}

local SSE_PROBE_BODY_CAP = 4 * 1024
local SSE_ATTACKER_ORIGIN = "https://hyperz-attacker.example"
local SSE_MAX_ENDPOINTS_PER_PAGE = 5

-- discover_sse_endpoints scans the page response for an SSE content-
-- type, scans the body for EventSource literals, resolves both
-- against the page URL, and returns a deduped + sorted list. Body-
-- derived URLs are dropped when they cannot be resolved (no host) or
-- when they ride a non-http(s) scheme.
local function discover_sse_endpoints(ctx, page_url)
  local seen = {}
  local function add(raw)
    local resolved = ctx.url.resolve(page_url, raw)
    if resolved == "" then return end
    local u = ctx.url.parse(resolved)
    if u == nil or u.host == "" then return end
    if u.scheme ~= "http" and u.scheme ~= "https" then return end
    seen[u.string] = true
  end

  -- Track 1: the page IS the SSE endpoint.
  local headers = ctx.page.headers
  if headers ~= nil and ctx.sse.is_event_stream(headers:get("Content-Type")) then
    add(ctx.page.url)
  end

  -- Track 2: EventSource literals in the body.
  local body = ctx.page.body
  if body ~= nil and body ~= "" then
    for _, raw in ipairs(ctx.sse.find_event_source_literals(body)) do
      add(raw)
    end
  end

  local out = {}
  for k in pairs(seen) do out[#out + 1] = k end
  table.sort(out)
  return out
end

-- classify_sse_cors returns (severity, title, detail) for the
-- observed CORS posture on an SSE endpoint, or three empty strings
-- when the posture does not expose the stream cross-origin.
local function sse_cred_suffix(acac)
  if acac then
    return " (Access-Control-Allow-Credentials: true compounds the impact by exposing the authenticated stream)"
  end
  return ""
end

local function classify_sse_cors(acao, acac, target)
  if acao == "" then return "", "", "" end

  if acao == "*" and acac then
    return "medium",
      "SSE endpoint sets wildcard CORS with credentials (spec-illegal)",
      string.format(
        "SSE endpoint %s returned Access-Control-Allow-Origin: * together with "
          .. "Access-Control-Allow-Credentials: true. The CORS spec forbids this combination; browsers refuse "
          .. "to deliver the stream, but the configuration indicates the credentials contract is misunderstood "
          .. "and is often paired with a more permissive variant on a sibling endpoint.", target)
  end

  if acao == "*" then
    return "medium",
      "SSE endpoint is readable from any origin",
      string.format(
        "SSE endpoint %s returned Access-Control-Allow-Origin: *. Any web page the victim visits can open an "
          .. "EventSource against this URL and read every event the server pushes. Credentials do NOT ride "
          .. "along on wildcard CORS, so authenticated stream content is not exposed directly - but stream "
          .. "content that does not require credentials (public counters, feature flag values, telemetry) is "
          .. "now harvestable cross-origin.", target)
  end

  if acao:lower() == "null" then
    return "medium",
      "SSE endpoint trusts the null origin",
      string.format(
        "SSE endpoint %s returned Access-Control-Allow-Origin: null. Sandboxed iframes, data: URIs, and file: "
          .. "contexts all present as the null origin; trusting it lets attacker-controlled documents in those "
          .. "contexts read the stream%s.", target, sse_cred_suffix(acac))
  end

  if acao:lower() == SSE_ATTACKER_ORIGIN:lower() then
    if acac then
      return "high",
        "SSE endpoint reflects arbitrary Origin with credentials",
        string.format(
          "SSE endpoint %s echoed the attacker-supplied Origin (%s) into Access-Control-Allow-Origin together "
            .. "with Access-Control-Allow-Credentials: true. Any web page the victim visits can open an "
            .. "EventSource against this URL with the victim's cookies attached and read the entire "
            .. "authenticated stream in real time.", target, SSE_ATTACKER_ORIGIN)
    end
    return "medium",
      "SSE endpoint reflects arbitrary Origin",
      string.format(
        "SSE endpoint %s echoed the attacker-supplied Origin (%s) into Access-Control-Allow-Origin. "
          .. "Credentials are not in the ACAO scope, but any origin can still open the stream and read the "
          .. "events.", target, SSE_ATTACKER_ORIGIN)
  end

  return "", "", ""
end

-- severity_cors_key collapses the relevant ACAO/ACAC posture into a
-- stable dedupe component. Two findings with different CORS shapes on
-- the same endpoint are genuinely different issues; identical shapes
-- collapse.
local function severity_cors_key(acao, acac)
  local creds = "0"
  if acac then creds = "1" end
  return acao:lower() .. ":" .. creds
end

-- build_sse_snippet renders the response summary used in Evidence
-- snippets: an "HTTP/1.1 STATUS TEXT" line followed by the relevant
-- CORS / cache headers.
local function build_sse_snippet(ctx, status, headers, body)
  local lines = {}
  lines[#lines + 1] = string.format("HTTP/1.1 %d %s", status, ctx.body.status_text(status))
  for _, name in ipairs({"Content-Type", "Access-Control-Allow-Origin",
                         "Access-Control-Allow-Credentials", "Cache-Control"}) do
    local v = headers:get(name)
    if v ~= "" then
      lines[#lines + 1] = string.format("%s: %s", name, v)
    end
  end
  local out = table.concat(lines, "\n") .. "\n"
  if body ~= nil and body ~= "" then
    out = out .. "\n" .. body
  end
  return out
end

-- probe_endpoint sends one GET with a foreign Origin against target
-- and returns a finding table or nil when the posture is fine / the
-- response is not an SSE stream. Errors are reported via ctx:report
-- and surface as nil + error string up to check.run.
local function probe_endpoint(ctx, target)
  local req, mut_err = ctx.client:new_request {
    method = methods.get,
    url    = target,
    headers = {
      Accept          = "text/event-stream",
      Origin          = SSE_ATTACKER_ORIGIN,
      ["Cache-Control"] = "no-cache",
    },
  }
  if mut_err then return nil, mut_err end

  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, do_err end

  local ct = resp:headers():get("Content-Type")
  if not ctx.sse.is_event_stream(ct) then return nil end

  local acao_raw = resp:headers():get("Access-Control-Allow-Origin")
  local acao = acao_raw:gsub("^%s+", ""):gsub("%s+$", "")
  local acac_raw = resp:headers():get("Access-Control-Allow-Credentials")
  local acac_trimmed = acac_raw:gsub("^%s+", ""):gsub("%s+$", "")
  local acac = acac_trimmed:lower() == "true"

  local sev_key, title, detail = classify_sse_cors(acao, acac, target)
  if sev_key == "" then return nil end

  local body, truncated, rerr = resp:read_body_capped(SSE_PROBE_BODY_CAP)
  if rerr then
    ctx:report(string.format("sse-audit read %s: %s", target, rerr))
  end

  return {
    severity = severity[sev_key],
    target   = target,
    url      = target,
    title    = title,
    detail   = detail,
    evidence = ctx.evidence.from_exchange {
      request   = req,
      response  = resp,
      body      = body,
      truncated = truncated,
      snippet   = build_sse_snippet(ctx, resp:status(), resp:headers(), body),
    },
    dedupe_parts = { "cors:" .. severity_cors_key(acao, acac) },
  }
end

function check.run(ctx)
  local page_u = ctx.url.parse(ctx.page.url)
  if page_u == nil or page_u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local endpoints = discover_sse_endpoints(ctx, ctx.page.url)
  if #endpoints == 0 then return nil end

  -- Eligibility: hard-gate on scope, then admit (a) exact-host
  -- endpoints, (b) any host the operator put on the allowlist, or
  -- (c) when scope is wide open, only same-registrable-domain
  -- siblings. Modern apps offload SSE to dedicated subdomains
  -- (events.target.com from app.target.com), so exact-host matching
  -- was missing the common case; the eTLD+1 fallback keeps the
  -- open-scope path from probing arbitrary third-party EventSource
  -- references found in body content.
  local scope_pinned = ctx.scope:has_hosts()
  local findings = {}
  local probed = 0
  for _, ep in ipairs(endpoints) do
    if probed >= SSE_MAX_ENDPOINTS_PER_PAGE then break end
    local ep_u = ctx.url.parse(ep)
    if ep_u ~= nil and ep_u.host ~= "" and ctx.scope:allows(ep) then
      local same_host = ep_u.hostname:lower() == page_u.hostname:lower()
      local eligible = same_host or scope_pinned
          or ctx.url.same_site(ep_u.hostname, page_u.hostname)
      if eligible then
        probed = probed + 1
        local f, err = probe_endpoint(ctx, ep)
        if err then
          ctx:report(string.format("sse-audit probe %s: %s", ep, err))
        elseif f then
          findings[#findings + 1] = f
        end
      end
    end
  end

  if #findings == 0 then return nil end
  return findings
end

return check
