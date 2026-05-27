-- csp-bypass: actively probes the three bypass paths the passive
-- csp-weak check can only theorize about:
--
--   1. Nonce reuse: re-fetch the page with cache-busting and compare
--      the nonces in script-src / style-src across the two responses.
--      A nonce that appears in both responses is a static string an
--      attacker can lift off any normal response and replay in an
--      injected <script nonce="...">.
--   2. JSONP on a whitelisted host: walk the script-src allowlist, find
--      sources that resolve to a known-JSONP CDN, and verify the bypass
--      by sending a canary callback request. JS content type AND the
--      canary echoed as a function call are required for confirmation;
--      a JSON error body that merely mentions the callback string does
--      not fire.
--   3. Base-URI hijack precondition: when base-uri is missing or set
--      permissively AND the page actually loads scripts via relative
--      URLs, an injected <base href> would retarget those loads.
--
-- Each sub-probe is independent; a transient failure in one does not
-- suppress findings from the others. Only when no findings come out
-- and at least one probe errored does the wholesale error propagate.

local check = {
  name  = "csp-bypass",
  level = "default",
  scope = "host",
  owasp = "A05:2021 Security Misconfiguration",
}

-- Forward declarations so check.run can call the per-probe helpers
-- before they're defined.
local probe_nonce_reuse, probe_jsonp_whitelist, probe_base_uri_hijack

function check.run(ctx)
  local u, _ = ctx.url.parse(ctx.page.url)
  if not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local snap, err = ctx:ensure_response { max_body = ctx.body.csp_bypass_body_cap() }
  if err then return nil, err end

  local enforcing = snap.headers:values("Content-Security-Policy")
  if #enforcing == 0 then
    -- csp-weak / security-headers already cover absent CSP; nothing
    -- for the bypass probes to bite on.
    return nil
  end
  local dirs = ctx.body.csp_parse_directives(enforcing[1])

  local findings = {}
  local first_err

  local f_nonce, err_nonce = probe_nonce_reuse(ctx, dirs)
  if err_nonce then
    ctx:report("csp-bypass nonce-reuse: " .. err_nonce)
    if not first_err then first_err = err_nonce end
  elseif f_nonce then
    findings[#findings + 1] = f_nonce
  end

  local jsonp_hits, err_jsonp = probe_jsonp_whitelist(ctx, dirs)
  if err_jsonp then
    ctx:report("csp-bypass jsonp: " .. err_jsonp)
    if not first_err then first_err = err_jsonp end
  end
  for _, f in ipairs(jsonp_hits or {}) do
    findings[#findings + 1] = f
  end

  local f_base = probe_base_uri_hijack(ctx, snap, dirs)
  if f_base then
    findings[#findings + 1] = f_base
  end

  if #findings == 0 and first_err then
    return nil, first_err
  end
  return findings
end

-- quoted joins a list of strings into a comma-separated `"a", "b"`
-- list for the per-finding detail text.
local function quoted(list)
  local out = {}
  for i, s in ipairs(list) do
    out[i] = string.format("%q", s)
  end
  return table.concat(out, ", ")
end

-- probe_nonce_reuse re-fetches the URL with a cache-busting query
-- param and compares nonces across the two responses. A nonce in both
-- responses fires; rotation works keeps things quiet. Bails when the
-- policy has no nonces (nothing to compare) or the second response
-- omits the CSP header (cannot claim reuse without a second sample).
function probe_nonce_reuse(ctx, dirs)
  local original = ctx.body.csp_nonce_values(dirs)
  if #original == 0 then return nil end

  local target = ctx.page.url
  local probe_url, err = ctx.url.append_query_param(target, "hyperz_nonce_probe", "1")
  if err then return nil, err end

  local req, nerr = ctx.client:new_request {
    method  = "GET",
    url     = probe_url,
    headers = {
      ["Cache-Control"] = "no-cache",
      Pragma            = "no-cache",
    },
  }
  if nerr then return nil, nerr end

  local resp, derr = ctx.client["do"](ctx.client, req)
  if derr then return nil, derr end

  local _, _, rerr = resp:read_body_capped(ctx.body.csp_bypass_body_cap())
  if rerr then return nil, rerr end

  local second_policies = resp:headers():values("Content-Security-Policy")
  if #second_policies == 0 then return nil end
  local second_dirs = ctx.body.csp_parse_directives(second_policies[1])
  local second_nonces = ctx.body.csp_nonce_values(second_dirs)
  if #second_nonces == 0 then return nil end

  local second_set = {}
  for _, n in ipairs(second_nonces) do second_set[n] = true end
  local reused, seen = {}, {}
  for _, n in ipairs(original) do
    if second_set[n] and not seen[n] then
      seen[n] = true
      reused[#reused + 1] = n
    end
  end
  if #reused == 0 then return nil end
  table.sort(reused)

  local detail = string.format(
    "Two consecutive responses from %s carry the same CSP nonce(s) in script-src/style-src: %s. CSP nonces must be unpredictable and unique per response - a reused nonce is a static string the attacker can lift from any normal response and embed in an injected <script nonce=\"...\">, defeating the policy until the value finally rotates. The bypass works against the same XSS chain CSP exists to stop.",
    target, quoted(reused))

  return {
    target      = target,
    url         = target,
    severity    = ctx.severity.high,
    title       = "CSP nonce reused across responses",
    detail      = detail,
    cwe         = "CWE-1004, CWE-330",
    owasp       = "A05:2021 Security Misconfiguration",
    remediation = "Generate a fresh, cryptographically random nonce per response (e.g. 16 bytes from a CSPRNG, base64url-encoded) and inject the same value into both the CSP header and every legitimate <script> / <style> tag in the body. Never derive the nonce from a static seed, a session ID, or a deployment-time constant.",
    evidence    = ctx.evidence.build {
      method  = "GET",
      url     = probe_url,
      status  = resp:status(),
      headers = resp:headers(),
      body    = "reused nonces: " .. table.concat(reused, ", "),
    },
    dedupe_parts = { "nonce-reuse" },
  }
end

-- probe_jsonp_whitelist walks the effective script-src allowlist,
-- picks out sources that would allow loading a script from a known-
-- JSONP CDN, and verifies the bypass by fetching the JSONP endpoint
-- with a canary callback. Per-probe failures (network, build) do not
-- suppress findings against other CDNs.
function probe_jsonp_whitelist(ctx, dirs)
  local script_srcs = dirs["script-src"]
  if not script_srcs then
    script_srcs = dirs["default-src"]
  end
  if not script_srcs then return nil end

  local canary = ctx.body.csp_bypass_callback_canary()
  local body_cap = ctx.body.csp_bypass_body_cap()
  local target = ctx.page.url

  local findings, first_err = {}, nil
  for _, probe in ipairs(ctx.body.csp_bypass_jsonp_probes()) do
    local matched, ok = ctx.body.csp_script_src_allows_host(script_srcs, probe.host)
    if ok then
      local probe_url = probe.url_tmpl .. canary
      local req, nerr = ctx.client:new_request { method = "GET", url = probe_url }
      if nerr then
        if not first_err then first_err = nerr end
      else
        local resp, derr = ctx.client["do"](ctx.client, req)
        if derr then
          if not first_err then first_err = derr end
        else
          local body, truncated, rerr = resp:read_body_capped(body_cap)
          if rerr then
            if not first_err then first_err = rerr end
          elseif ctx.body.csp_confirms_jsonp(resp:headers():get("Content-Type"), body, canary) then
            findings[#findings + 1] = {
              target      = target,
              url         = target,
              severity    = ctx.severity.high,
              title       = string.format("CSP script-src allowlists %s, which serves a JSONP bypass endpoint", probe.host),
              detail      = string.format(
                "The Content-Security-Policy on %s includes a source that allows scripts from %s (matched: %q). That host serves a JSONP endpoint at %s which echoes the supplied callback parameter into executable JavaScript. An attacker with HTML injection on %s can load <script src=\"%sEVIL\"></script> where EVIL is an attacker-controlled function name; the script then executes EVIL(...) under this origin and the CSP allows it because the host is on the script-src allowlist. The probe confirmed the bypass by fetching the endpoint with callback=%s and observing a JavaScript response containing the callback as a function call.",
                target, probe.host, matched, probe.url_tmpl, target, probe.url_tmpl, canary),
              cwe         = "CWE-829, CWE-79",
              owasp       = "A05:2021 Security Misconfiguration",
              remediation = string.format("Drop %s from script-src, or - if it is genuinely required - restrict it to a specific path prefix that excludes the JSONP endpoint (browsers honour path-bounded sources). Better: switch to a strict, nonce-based policy where third-party CDN hosts are not required at all. JSONP-on-allowlisted-CDN is one of the most heavily documented CSP bypass patterns; any CDN in a script-src deserves the same audit.", probe.host),
              evidence    = ctx.evidence.build {
                method  = "GET",
                url     = probe_url,
                status  = resp:status(),
                headers = resp:headers(),
                body    = ctx.body.csp_bypass_jsonp_snippet(body, truncated),
              },
              dedupe_parts = { "jsonp:" .. probe.host },
            }
          end
        end
      end
    end
  end
  if #findings == 0 and first_err then return nil, first_err end
  return findings
end

-- probe_base_uri_hijack fires when base-uri is missing / permissive
-- AND the page actually depends on relative <script src> loads. Both
-- halves are required: missing base-uri without relative srcs is just
-- the passive csp-weak nudge, and relative srcs with base-uri 'none'
-- are inert.
function probe_base_uri_hijack(ctx, snap, dirs)
  if not ctx.body.csp_base_uri_hijackable(dirs) then return nil end
  if not snap.body or snap.body == "" then return nil end
  local relatives = ctx.body.csp_relative_script_srcs(snap.body)
  if #relatives == 0 then return nil end

  local preview = {}
  for i = 1, math.min(5, #relatives) do preview[i] = relatives[i] end

  local target = ctx.page.url
  local detail = string.format(
    "Response from %s does not constrain base-uri (or constrains it permissively) AND loads %d script(s) via relative URLs. An attacker with HTML injection can place <base href=\"//evil/\"> in the document; every relative script src below then resolves to evil/ on the next load. base-uri does NOT inherit from default-src, so a tight default-src is not enough on its own. Relative srcs observed (first %d shown): %s.",
    target, #relatives, #preview, quoted(preview))

  return {
    target      = target,
    url         = target,
    severity    = ctx.severity.medium,
    title       = "Base-URI hijack is exploitable on this page",
    detail      = detail,
    cwe         = "CWE-1021, CWE-79",
    owasp       = "A05:2021 Security Misconfiguration",
    remediation = "Add base-uri 'none' (or 'self') to the CSP. Once base-uri is constrained, an injected <base> tag cannot retarget relative URLs and the rest of the policy regains its grip on script loading.",
    evidence    = ctx.evidence.build {
      method  = "GET",
      url     = target,
      status  = snap.status,
      headers = snap.headers,
      body    = "relative script srcs: " .. table.concat(relatives, ", "),
    },
    dedupe_parts = { "base-uri-hijack" },
    -- One per page, not per host: base-uri exploitability depends on
    -- the per-page set of relative script srcs.
    dedupe_scope = "page",
  }
end

return check
