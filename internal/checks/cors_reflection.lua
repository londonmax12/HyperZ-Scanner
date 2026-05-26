-- cors-reflection: Lua port of internal/checks/cors_reflection.go.
--
-- Active probe complementing cors-config. Sends crafted Origin
-- headers and inspects Access-Control-Allow-Origin for echoes:
--
--   * "verbatim" canary on https://hyperz-canary.invalid - the
--     baseline probe, fired at every active level. RFC 2606 .invalid
--     guarantees no legitimate allowlist contains the host so any
--     reflection is confirmed reflection, not coincidence.
--   * "null-origin" - aggressive-only. Servers that trust the spec's
--     sandboxed-iframe origin accept any sandboxed attacker frame.
--   * "prefix-collision" - aggressive-only. Origin shaped as
--     <targetHost>.hyperz-canary.invalid catches servers that
--     prefix-match on the target host.
--
-- One consolidated finding emitted when any probe confirms.
-- Severity high when any technique was paired with ACAC: true
-- (credentialed cross-origin reads); medium otherwise.

local check = {
  name        = "cors-reflection",
  level       = "default",
  scope       = "host",
  cwe         = "CWE-942",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Validate the request Origin against a hardcoded allowlist before echoing it. If credentialed cross-origin access is not required, drop Access-Control-Allow-Credentials. Never return Access-Control-Allow-Origin: <whatever the client sent>.",
}

local CANARY_HOST = "hyperz-canary.invalid"
local CANARY      = "https://" .. CANARY_HOST
local BODY_CAP    = 4 * 1024

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

-- probe_specs returns the probe tuples for the active level. The
-- "verbatim" baseline always fires; aggressive scans add null-origin
-- and prefix-collision shapes that catch common allowlist bypasses.
local function probe_specs(ctx, target_host)
  local specs = {{
    technique = "verbatim",
    origin    = CANARY,
    confirms  = function(acao, origin) return acao == origin end,
  }}
  if not ctx:level_at_least("aggressive") then
    return specs
  end
  specs[#specs + 1] = {
    technique = "null-origin",
    origin    = "null",
    confirms  = function(acao) return string.lower(acao) == "null" end,
  }
  specs[#specs + 1] = {
    technique = "prefix-collision",
    origin    = "https://" .. target_host .. "." .. CANARY_HOST,
    confirms  = function(acao, origin) return acao == origin end,
  }
  return specs
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then
    return nil
  end
  if not ctx.scope:allows(ctx.page.url) then
    return nil
  end

  local hits = {}
  local first_err
  for _, spec in ipairs(probe_specs(ctx, u.host)) do
    local req, nerr = ctx.client:new_request {
      method  = "GET",
      url     = ctx.page.url,
      headers = { Origin = spec.origin },
    }
    if nerr then
      ctx:report("cors-reflection build req (" .. spec.technique .. "): " .. nerr)
      if not first_err then first_err = nerr end
    else
      local resp, derr = ctx.client["do"](ctx.client, req)
      if derr then
        ctx:report("cors-reflection probe " .. spec.technique .. ": " .. derr)
        if not first_err then first_err = derr end
      else
        local acao = trim(resp:headers():get("Access-Control-Allow-Origin"))
        if spec.confirms(acao, spec.origin) then
          local acac = string.lower(trim(resp:headers():get("Access-Control-Allow-Credentials"))) == "true"
          local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
          if rerr then
            ctx:report("cors-reflection read body (" .. spec.technique .. "): " .. rerr)
            if not first_err then first_err = rerr end
          else
            hits[#hits + 1] = {
              technique = spec.technique,
              origin    = spec.origin,
              acao      = acao,
              acac      = acac,
              req       = req,
              resp      = resp,
              body      = body,
              truncated = truncated,
            }
          end
        end
      end
    end
  end

  if #hits == 0 then
    -- Same wholesale-failure rule open-redirect uses: only surface an
    -- error when no probes produced findings.
    if first_err then return nil, first_err end
    return nil
  end

  local sev = "medium"
  for _, h in ipairs(hits) do
    if h.acac then sev = "high"; break end
  end

  local techniques = {}
  local lines = {}
  for _, h in ipairs(hits) do
    techniques[#techniques + 1] = h.technique
    lines[#lines + 1] = string.format(
      "- %s: probe sent Origin: %s -> Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s",
      h.technique, h.origin, h.acao, tostring(h.acac))
  end

  local first = hits[1]
  return {{
    severity = ctx.severity[sev],
    title    = "CORS reflects attacker-controlled Origin (" .. table.concat(techniques, ", ") .. ")",
    detail   = string.format(
      "Confirmed by sending crafted Origin headers against %s. The server echoed each probe Origin into Access-Control-Allow-Origin, so a page hosted on any attacker-controlled origin can issue cross-origin reads against this host.\n%s",
      ctx.page.url, table.concat(lines, "\n")),
    evidence = ctx.evidence.from_exchange {
      request   = first.req,
      response  = first.resp,
      body      = first.body,
      truncated = first.truncated,
    },
    dedupe_parts = { "reflection" },
  }}
end

return check
