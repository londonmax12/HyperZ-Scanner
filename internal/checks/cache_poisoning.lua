-- cache-poisoning: two arms.
--   1. Unkeyed-header poisoning. For each curated probe header
--      (X-Forwarded-Host / -Scheme / -Proto, X-Original-URL,
--      X-Rewrite-URL), send the probe and look for the canary in
--      the response body or selected headers (and, for the rewrite
--      probes, accept a response that meaningfully diverged from
--      baseline). When the cache is not keyed on the probe header
--      (Vary check) and the baseline carries cache hints, the bug is
--      a stored poisoning primitive. Severity High.
--   2. Cache deception. Append a static-asset suffix to the path; a
--      vulnerable server returns the authenticated HTML the original
--      path returns. Intermediate caches with extension-based rules
--      store it for arbitrary retrieval. Severity High (Medium when
--      the upstream sets Cache-Control: no-store / private).

local check = {
  name        = "cache-poisoning",
  level       = "default",
  scope       = "host",
  cwe         = "CWE-444",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Add the header to the cache key (Vary or the CDN's surrogate-key config) so a poisoned response can't be served back to other users. "
                .. "Better: stop reflecting reverse-proxy hints into generated URLs - derive absolute URLs from configuration, not from request headers. "
                .. "For X-Original-URL / X-Rewrite-URL specifically, ignore the header at the application layer and rely solely on the routed path.",
  tier        = "active",
}

local BODY_CAP = 16 * 1024

local function vary_keyed(vary_set, header_name)
  local lower = string.lower(header_name)
  for _, name in ipairs(vary_set) do
    if name == "*" or name == lower then return true end
  end
  return false
end

local function probe_unkeyed_header(ctx, target, probe, base_status, base_body, base_vary_header, vary_set)
  -- The probe URL appends a random cachebuster query parameter so the
  -- poisoned response a vulnerable cache stores lands on a key no
  -- organic request will reach. Without it, firing the probe at the
  -- canonical (method, path, query) would poison the exact key real
  -- users hit.
  local probe_target, ptu_err = ctx.body.cache_poison_probe_url(target)
  if ptu_err then return nil, ptu_err end

  local req, mut_err = ctx.client:new_request{
    method  = "GET",
    url     = probe_target,
    headers = { [probe.header] = probe.value },
  }
  if mut_err then return nil, mut_err end

  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, do_err end
  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, rerr end

  local headers = resp:headers()
  local where, ok = ctx.body.cache_poison_find_reflection(probe.canary, headers, body, base_body)
  if not ok and probe.kind == "reflection-or-diverged" then
    if ctx.body.cache_poison_response_diverged(resp:status(), body, base_status, base_body) then
      where = "response shape changed vs. baseline"
      ok = true
    end
  end
  if not ok then return nil end

  if vary_keyed(vary_set, probe.header) then return nil end

  local probe_url = req:url()
  local vary_desc = "none"
  if base_vary_header and base_vary_header ~= "" then vary_desc = base_vary_header end
  return {
    severity = ctx.severity.high,
    url      = probe_url,
    title    = string.format("Web cache poisoning via unkeyed header %s", probe.header),
    detail   = string.format(
      "%s The probe sent %s: %s and observed the canary at %s. "
        .. "The baseline response carries cache hints (Cache-Control/Age/X-Cache) but Vary is %q, "
        .. "so the intermediate cache will not partition entries on this header. "
        .. "An attacker can issue one crafted request and every subsequent victim served from cache receives the poisoned response.",
      probe.deception_message, probe.header, probe.value, where, vary_desc),
    evidence = ctx.evidence.from_exchange {
      request   = req,
      response  = resp,
      body      = body,
      truncated = truncated,
    },
    dedupe_parts = { "unkeyed-header", "name:" .. string.lower(probe.header) },
  }
end

local function probe_cache_deception(ctx, target, base_status, base_body, base_content_type)
  if not ctx.body.is_html_ct(base_content_type) then return nil end

  local deceived, durl_err = ctx.body.cache_poison_deception_url(target)
  if durl_err then return nil, durl_err end
  if deceived == "" then return nil end

  local req, mut_err = ctx.client:new_request{ method = "GET", url = deceived }
  if mut_err then return nil, mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, do_err end

  if resp:status() ~= 200 then return nil end
  local resp_headers = resp:headers()
  if not ctx.body.is_html_ct(resp_headers:get("Content-Type")) then return nil end

  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, rerr end

  if not ctx.body.cache_poison_bodies_match(body, base_body) then return nil end

  local severity = ctx.severity.high
  if ctx.body.cache_poison_cc_forbids_storage(resp_headers:get("Cache-Control")) then
    severity = ctx.severity.medium
  end

  local suffix = ctx.payloads.cache_poison_deception_suffix()
  local u = ctx.url.parse(target)
  local base_path = (u and u.path) or "/"
  return {
    severity = severity,
    url      = deceived,
    title    = "Web cache deception via static-asset path suffix",
    detail   = string.format(
      'Appending %q to the authenticated path %q produced a 200 response whose body matched the original. '
        .. 'Caches in front of the application apply extension-based rules (.css, .js, .jpg are typically cacheable) and will store the response '
        .. 'under the deception URL. An attacker who lures a victim to /<auth-path>%s causes the cache to retain the victim\'s authenticated HTML; '
        .. 'the attacker can then fetch the same URL anonymously and retrieve the stored content.',
      suffix, base_path, suffix),
    evidence = ctx.evidence.from_exchange {
      request   = req,
      response  = resp,
      body      = body,
      truncated = truncated,
    },
    dedupe_scope = "page",
    dedupe_parts = { "cache-deception" },
  }
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local snap, ensure_err = ctx:ensure_response { max_body = BODY_CAP }
  if ensure_err then return nil end
  if snap.status < 200 or snap.status >= 400 then return nil end

  local findings = {}
  local first_err

  -- Unkeyed-header arm: only runs when the baseline carries cache
  -- markers. Without an intermediary cache the worst case is per-
  -- request reflection (covered by host-header-injection), not a
  -- stored poison hitting every later victim.
  if ctx.body.cache_poison_has_cache_hint(snap.headers) then
    local vary_header = snap.headers:get("Vary")
    local vary_set = ctx.body.cache_poison_parse_vary(vary_header)
    for _, probe in ipairs(ctx.payloads.cache_poison_header_probes()) do
      local f, err = probe_unkeyed_header(ctx, ctx.page.url, probe, snap.status, snap.body, vary_header, vary_set)
      if err then
        ctx:report("cache-poisoning header " .. probe.header .. ": " .. err)
        if not first_err then first_err = err end
      elseif f then
        findings[#findings + 1] = f
      end
    end
  end

  -- Cache-deception arm: gated on a path that looks auth-bearing
  -- (or every page at LevelAggressive). The bug is at the server,
  -- so absence of a cache hint on the baseline does not disprove
  -- exploitability; a downstream CDN with extension-based rules
  -- will still store the response.
  if ctx.body.cache_poison_is_auth_likely_path(u.path) or ctx:level_at_least("aggressive") then
    local f, err = probe_cache_deception(ctx, ctx.page.url, snap.status, snap.body, snap.headers:get("Content-Type"))
    if err then
      ctx:report("cache-deception probe: " .. err)
      if not first_err then first_err = err end
    elseif f then
      findings[#findings + 1] = f
    end
  end

  if first_err and #findings == 0 then return nil, first_err end
  return findings
end

return check
