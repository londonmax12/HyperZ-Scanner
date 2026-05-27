-- csp-weak: inspects a present Content-Security-Policy header value
-- (enforcing first, Report-Only fallback) and emits one consolidated
-- finding listing every weakness in the policy: missing object-src /
-- base-uri, 'unsafe-inline' / 'unsafe-eval' in script-src, wildcard
-- sources, scheme-only allowlists, Report-Only-without-enforcement,
-- and so on. Directive parsing and matchers live behind
-- ctx.body.analyze_csp so the spec-fatal duplicate-detection and the
-- keyword / hash / nonce matchers stay in exactly one place.

local check = {
  name        = "csp-weak",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-1173, CWE-79",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Aim for a strict, nonce-based policy: default-src 'none'; script-src 'nonce-{random}' 'strict-dynamic'; style-src 'nonce-{random}'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'. "
                .. "Drop 'unsafe-inline' and 'unsafe-eval' from script-src; refactor inline handlers and string-eval call sites instead of allowlisting them. "
                .. "For incremental rollout, deploy the strict policy via Content-Security-Policy-Report-Only first, monitor violation reports, and switch to enforcement once clean.",
  tier        = "passive",
}

local SEVERITY_RANK = { info = 0, low = 1, medium = 2, high = 3, critical = 4 }

function check.run(ctx)
  local snap, err = ctx:ensure_response()
  if err then return nil, err end

  local enforcing = snap.headers:values("Content-Security-Policy")
  local report_only = snap.headers:values("Content-Security-Policy-Report-Only")
  if #enforcing == 0 and #report_only == 0 then
    -- Absence is security-headers' job; nothing for us to say.
    return nil
  end

  local result = ctx.body.analyze_csp(enforcing, report_only)
  if #result.weaknesses == 0 then return nil end

  local max_sev = "info"
  local details = {}
  local id_parts = {}
  for _, w in ipairs(result.weaknesses) do
    if SEVERITY_RANK[w.severity] > SEVERITY_RANK[max_sev] then
      max_sev = w.severity
    end
    details[#details + 1] = string.format("%s [%s]: %s", w.directive, w.severity, w.detail)
    id_parts[#id_parts + 1] = w.directive .. ":" .. w.id
  end

  local title
  if #result.weaknesses == 1 then
    title = "Content-Security-Policy has 1 weakness"
  else
    title = string.format("Content-Security-Policy has %d weaknesses", #result.weaknesses)
  end
  if result.is_report_only then
    title = title .. " (Report-Only)"
  end

  local lead_in = string.format(
    "Response from %s ships a Content-Security-Policy but the policy contains directives that materially reduce or eliminate its XSS / framing protection. Each entry below names the weak directive, the resulting risk, and how to tighten it.",
    ctx.page.url)

  return {{
    severity = ctx.severity[max_sev],
    title    = title,
    detail   = lead_in,
    details  = details,
    evidence = ctx.evidence.build {
      method  = "GET",
      url     = ctx.page.url,
      status  = snap.status,
      headers = snap.headers,
    },
    dedupe_parts = id_parts,
  }}
end

return check
