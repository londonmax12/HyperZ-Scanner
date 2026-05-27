-- jwt-vulns: probes JSON Web Token validators for the common
-- implementation bugs that turn a signature-bearing token into a
-- forgeable bearer: alg=none acceptance, weak HS256 secrets, kid
-- header treated as a filesystem path or unsanitised SQL fragment,
-- asymmetric->HMAC algorithm confusion, JOSE crit-header abuse, and
-- jku/x5u acceptance of attacker-controlled key URLs (OOB).
--
-- The per-probe scan algorithm (HMAC sign with attacker keys, RSA
-- public-key extraction, base64url codec, OOB canary fan-out, oracle
-- build, RFC 7515 alg pinning) lives behind ctx.jwt.scan, which
-- returns a list of (kind, target, params) facts. This file iterates
-- the facts, dispatches on kind, and composes one finding per fact.
--
-- check.drain handles jku/x5u OOB confirmation; the scanner calls it
-- once after the wait window.

local check = {
  name           = "jwt-vulns",
  level          = levels.aggressive,
  scope          = scopes.host,
  budget_seconds = 180,
  tier           = tiers.active,
  pollute        = true,
}

-- compose_finding wraps the bridge-supplied params into a Lua finding
-- table. The prose is RFC 7515 / RFC 7519 spec-grounded so we pass it
-- through unchanged; what's owned here is dedupe-key shape, severity
-- floor, and evidence wrapping.
local function compose_finding(ctx, fact)
  local p = fact.params or {}
  return {
    severity = p.severity or severity.high,
    target   = fact.target,
    url      = fact.target,
    title    = p.title or "",
    detail   = p.detail or "",
    cwe      = p.cwe or "",
    owasp    = p.owasp or "",
    remediation = p.remediation or "",
    evidence = ctx.evidence.build {
      method  = p.evidence_method or "GET",
      url     = p.evidence_url or fact.target,
      status  = p.evidence_status or 0,
      body    = p.evidence_snippet or "",
    },
    -- Pass the bridge-computed dedupe key through verbatim so a
    -- token observed on N crawled pages collapses to one finding.
    -- The key shape depends on the per-kind suffix the scan picked,
    -- which is internal to the scan algorithm rather than this rule's
    -- prose.
    dedupe_key = p.dedupe_key or ctx.dedupe.key {
      check  = check.name,
      scope  = scopes.host,
      target = fact.target,
      parts  = { fact.kind },
    },
  }
end

function check.run(ctx)
  local facts, err = ctx.jwt.scan()
  if err then
    return nil, err
  end
  if facts == nil or #facts == 0 then return nil end
  local findings = {}
  for _, fact in ipairs(facts) do
    findings[#findings + 1] = compose_finding(ctx, fact)
  end
  return findings
end

-- check.drain surfaces jku/x5u OOB-confirmation findings after the
-- scanner's wait window. ctx.jwt.drain translates the active-phase
-- callback registrations into facts and one finding fires per
-- callback. The bridge call is cheap when no OOB server was
-- configured (drain returns nil immediately).
function check.drain(ctx)
  local facts = ctx.jwt.drain()
  if facts == nil or #facts == 0 then return nil end
  local findings = {}
  for _, fact in ipairs(facts) do
    findings[#findings + 1] = compose_finding(ctx, fact)
  end
  return findings
end

return check
