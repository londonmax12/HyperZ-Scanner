-- nextjs-image-ssrf: probes the Next.js Image Optimization endpoint
-- (`/_next/image?url=...&w=...&q=...`) for an open allow-list that
-- forwards attacker-supplied URLs into the server-side fetcher.
--
-- Next.js' built-in image optimizer takes a `url` query parameter,
-- fetches it server-side, transforms it (resize, format), and serves
-- the result. The fetcher is gated by `images.remotePatterns` /
-- `images.domains` in next.config.js: only allow-listed hosts are
-- fetched, everything else is rejected with a 400. Misconfigurations
-- (`remotePatterns: [{ hostname: "**" }]`, missing config altogether
-- in older Next.js, or a placeholder like `domains: ["*"]`) turn the
-- endpoint into a fully-controllable SSRF: an attacker reads internal
-- HTTP services, cloud metadata endpoints, and any host the runtime
-- can route to.
--
-- Detection is OOB-only. The check registers a canary URL with the
-- listener and threads it through `/_next/image?url=<canary>`; if the
-- canary observes a hit during drain, the allow-list is open. A
-- correctly-configured site rejects the URL upfront and the listener
-- sees nothing - no false-positive surface. When the scan was started
-- without --oob the active probe is silently skipped: there's no
-- reliable in-band signal that distinguishes "fetched and discarded"
-- from "rejected at the allow-list" without observing the egress.

local check = {
  name        = "nextjs-image-ssrf",
  level       = levels.default,
  scope       = scopes.host,
  cwe         = "CWE-918",
  owasp       = "A10:2021 Server-Side Request Forgery (SSRF)",
  remediation = "Tighten `images.remotePatterns` (or the legacy `images.domains`) in next.config.js to the explicit list of hosts the application is allowed to load images from. Avoid wildcard hostnames (`**`). On older Next.js without remotePatterns, upgrade to a version that supports it - the legacy `domains` list does not enforce path or scheme. If the optimizer is unused, disable it (`images: { unoptimized: true }`) or block `/_next/image*` at the edge.",
  tier        = tiers.active,
  applies_to  = { framework = { framework.nextjs } },
}

-- IMAGE_PARAMS are the minimum query parameters /_next/image requires
-- to consider a request well-formed. `w` (width) must be one of the
-- configured device sizes; 128 is in the default set on every shipping
-- major. `q` (quality) is 1-100; 75 is the framework default.
local IMAGE_PARAMS = "&w=128&q=75"

-- ssrf_url_encode percent-encodes a canary URL for safe placement in
-- the `url=` query slot. /_next/image itself percent-decodes once
-- before allow-list checking, so a single-pass encode is correct;
-- double-encoding would cause Next.js to treat literal `%3A` as the
-- hostname character set and reject the URL pre-fetch.
local function ssrf_url_encode(u)
  return (u:gsub("([^%w%-_%.~])", function(c)
    return string.format("%%%02X", string.byte(c))
  end))
end

function check.run(ctx)
  if not ctx.oob:attached() then return nil end

  local host_root, ok = ctx.host:claim_from_page()
  if not ok then return nil end

  local canary = ctx.oob:register{
    target = host_root,
    sink   = "_next/image",
  }
  if canary == nil then return nil end

  local probe_url = host_root .. "/_next/image?url=" .. ssrf_url_encode(canary.http_url) .. IMAGE_PARAMS
  local resp, _, err = ctx.client:fetch{
    method   = methods.get,
    url      = probe_url,
    body_cap = body_caps.small,
  }
  if err then return nil, err end
  -- Drain a tiny chunk on success so the connection returns cleanly;
  -- the listener-side hit is the signal, not the response body.
  if resp ~= nil then resp:read_body_capped(256) end
  return nil
end

-- Drain emits one finding per registration whose canary observed a
-- callback. Severity is critical because an open allow-list means
-- arbitrary attacker-controlled URLs reach the Next.js process'
-- network namespace - cloud metadata, internal admin APIs, and any
-- host the runtime can route to are in scope.
function check.drain(ctx)
  if not ctx.oob:attached() then return nil end
  local findings = {}
  for _, reg in ipairs(ctx.oob:registrations()) do
    local hits = ctx.oob:hits(reg.token)
    if #hits > 0 then
      local extra  = reg.extra or {}
      local target = extra.target or ""
      local hit    = hits[1]
      findings[#findings + 1] = {
        severity = severity.critical,
        target   = target,
        url      = target,
        title    = "Next.js Image Optimization SSRF via open /_next/image allow-list",
        detail   = string.format(
          "GET %s/_next/image?url=<canary> caused the runtime to fetch the canary URL; the OOB listener " ..
          "recorded a hit (method=%s, source=%s, user-agent=%q, %d hit(s)). The `images.remotePatterns` / " ..
          "`images.domains` allow-list permits arbitrary attacker-supplied hosts, turning the image " ..
          "optimizer into a server-side fetcher for any URL the Next.js process can route to (cloud " ..
          "metadata endpoints, internal admin APIs, intranet hosts).",
          target, hit.method, hit.source_addr, hit.user_agent or "", #hits),
        evidence = ctx.evidence.build{
          method  = methods.get,
          url     = target,
          snippet = string.format(
            "Canary URL: %s\nFirst hit: %s %s from %s at unix=%d\nUser-Agent: %s\nTotal hits: %d\n",
            reg.http_url, hit.method, hit.path, hit.source_addr,
            hit.timestamp_unix, hit.user_agent or "", #hits),
        },
        dedupe_parts = { "sink:_next/image", "oob" },
      }
    end
  end
  return findings
end

return check
