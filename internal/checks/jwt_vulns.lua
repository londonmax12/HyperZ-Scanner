-- jwt-vulns: Lua port of internal/checks/jwt.go (and friends).
--
-- Probes JSON Web Token validators for the common implementation
-- bugs that turn a signature-bearing token into a forgeable bearer:
-- alg=none acceptance, weak HS256 secrets, kid header treated as a
-- filesystem path or unsanitised SQL fragment, asymmetric->HMAC
-- algorithm confusion, JOSE crit-header abuse, and jku/x5u
-- acceptance of attacker-controlled key URLs (OOB).
--
-- Architecture: the per-probe SCAN ALGORITHM (HMAC sign with
-- attacker keys, RSA public-key extraction, base64url codec, OOB
-- canary fan-out, oracle build, RFC 7515 alg pinning) lives in Go
-- and is exposed through ctx.jwt.scan as a raw FACTS list. Each
-- fact is a (kind, target, params) tuple; the Lua port iterates,
-- dispatches on kind, and composes one Finding per fact with the
-- catalog metadata (severity, title, detail, CWE, OWASP,
-- remediation, dedupe key, evidence) declared here. This is the
-- same shape the subdomain-takeover port uses for the same reason:
-- the scan code is crypto-heavy and tightly tested; the prose is
-- what an operator might want to rewrite without recompiling Go.
--
-- Drain: jku/x5u OOB confirmation flows through check.drain, which
-- the scanner calls once per LuaCheck after the wait window. The
-- drain bridge reads from the same Go-side JWTVulns instance the
-- scan path uses so OOB findings still surface when the Lua port
-- has shadowed the Go check via mergeLuaOverrides.

local check = {
  name           = "jwt-vulns",
  level          = "aggressive",
  scope          = "host",
  budget_seconds = 180,
  pollute        = true,
}

-- compose_finding lifts the bridge-supplied params (which already
-- carry every text/severity/CWE/OWASP/remediation default the Go
-- composer chose) into a Lua finding table. The Lua side owns the
-- decision to pass through verbatim vs. rewrite; for jwt-vulns the
-- Go-side text is RFC 7515 / RFC 7519 spec-grounded and rewriting it
-- in Lua would risk drifting away from that ground truth, so the
-- port passes the prose through unchanged. The Lua-OWNED parts are:
-- dedupe-key shape, severity floor (defaulting to the bridge's
-- recommendation), evidence wrapping.
local function compose_finding(ctx, fact)
  local p = fact.params or {}
  return {
    severity = p.severity or ctx.severity.high,
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
    -- token observed on N crawled pages collapses to one finding
    -- exactly as the Go check would. Lua composing its own key
    -- here would require re-deriving the kind suffix the Go
    -- check used per probe, which is fragile - the key shape is
    -- internal to the scan algorithm, not the rule's prose.
    dedupe_key = p.dedupe_key or ctx.dedupe.key {
      check  = check.name,
      scope  = "host",
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
-- scanner's wait window. The Go-side JWTVulns observed the canary
-- callbacks during the active phase; Drain just translates the
-- registrations into facts and the Lua composer emits one finding
-- per callback. Modules that omit drain return no findings; this
-- one always declares it because the bridge call is cheap when no
-- OOB server was configured (DrainFacts returns nil immediately).
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
