-- cors-config: Lua port of internal/checks/cors_config.go.
--
-- Passive inspection of Access-Control-Allow-Origin /
-- Access-Control-Allow-Credentials on the cached response. Three
-- shapes fire findings:
--
--   * ACAO=*  with ACAC=true   -> high (CORS-spec violation; signals
--                                       the credentials contract is
--                                       misunderstood)
--   * ACAO=null                -> medium (sandboxed iframes / data:
--                                         pages all present as null)
--   * specific cross-origin ACAO with ACAC=true
--                              -> high (origin-reflection shape)
--
-- No active Origin probe is sent (that's cors-reflection's job).

local check = {
  name  = "cors-config",
  level = "passive",
  scope = "host",
  cwe   = "CWE-942",
  owasp = "A05:2021 Security Misconfiguration",
}

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

local function cred_suffix(acac)
  if acac then
    return " (Access-Control-Allow-Credentials: true compounds the impact by exposing authenticated responses)"
  end
  return ""
end

-- same_origin_as mirrors sameOriginAs: scheme + host (case-insensitive)
-- must match. Default-port mismatches are intentionally treated as
-- distinct because url.Parse keeps the explicit port in u.Host.
local function same_origin_as(ctx, acao, target_url)
  local a, aerr = ctx.url.parse(acao)
  local t, terr = ctx.url.parse(target_url)
  if aerr or terr or not a or not t then return false end
  if a.scheme == "" or a.host == "" or t.scheme == "" or t.host == "" then
    return false
  end
  return string.lower(a.scheme) == string.lower(t.scheme)
     and string.lower(a.host)   == string.lower(t.host)
end

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  local acao = trim(snap.headers:get("Access-Control-Allow-Origin"))
  if acao == "" then return nil end
  local acac = string.lower(trim(snap.headers:get("Access-Control-Allow-Credentials"))) == "true"

  local evidence = ctx.evidence.build {
    method  = "GET",
    url     = ctx.page.url,
    status  = snap.status,
    headers = snap.headers,
  }

  if acao == "*" then
    -- `*` alone is the intentionally-public marker and benign;
    -- the spec-violating combination is what we flag.
    if not acac then return nil end
    return {{
      severity    = ctx.severity.high,
      title       = "CORS allows any origin with credentials",
      detail      = string.format(
        "response from %s set Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. The CORS spec forbids this combination; browsers refuse it, but the configuration indicates the credentials contract is misunderstood and is often paired with a permissive handler that this passive scan did not reach.",
        ctx.page.url),
      remediation = "Drop Access-Control-Allow-Credentials, or replace * with a hardcoded allowlist of trusted origins. The two together are invalid per the CORS spec.",
      evidence    = evidence,
      dedupe_parts = { "wildcard-with-credentials" },
    }}
  end

  if string.lower(acao) == "null" then
    -- `null` is presented by sandboxed iframes, data: URIs, file:
    -- pages, and certain redirect chains - the very contexts an
    -- attacker can engineer; trusting it is the canonical CWE-942.
    return {{
      severity    = ctx.severity.medium,
      title       = "CORS trusts the null origin",
      detail      = string.format(
        "response from %s set Access-Control-Allow-Origin: null. Sandboxed iframes, data: URIs, and file: contexts all present as the null origin, so any of them can issue cross-origin reads against this host%s.",
        ctx.page.url, cred_suffix(acac)),
      remediation = "Remove null from the allowed origins. Use an explicit allowlist of HTTPS origins instead.",
      evidence    = evidence,
      dedupe_parts = { "null-origin" },
    }}
  end

  -- Specific origin in ACAO. Same-origin echoes are benign
  -- normalization; only cross-origin + credentials is exploitable
  -- (origin-reflection or static foreign trust).
  if not acac or same_origin_as(ctx, acao, ctx.page.url) then
    return nil
  end
  return {{
    severity    = ctx.severity.high,
    title       = "CORS trusts a foreign origin with credentials",
    detail      = string.format(
      "response from %s set Access-Control-Allow-Origin: %s with Access-Control-Allow-Credentials: true. This is the shape produced by servers that reflect the caller's Origin verbatim; if so, any attacker-controlled page can read authenticated responses from this host.",
      ctx.page.url, acao),
    remediation = "Validate the request Origin against a hardcoded allowlist before echoing it. Never reflect Origin alongside Access-Control-Allow-Credentials: true.",
    evidence    = evidence,
    dedupe_parts = { "foreign-origin-with-credentials" },
  }}
end

return check
