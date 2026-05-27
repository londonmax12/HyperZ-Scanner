-- drupal-changelog-disclosure: flags Drupal installs whose
-- /CHANGELOG.txt file is reachable to anonymous requests. The file
-- ships with the default Drupal 7 install layout, and many Drupal 7
-- sites still expose it. Its leading line is a verbatim "Drupal
-- <version>, <release-date>" string, so an attacker reading the file
-- learns the exact build the operator is running, which makes
-- targeted exploit selection trivial.
--
-- Drupal 8 changed the install layout and no longer ships
-- /CHANGELOG.txt by default. The file is not a security patch
-- target - Drupal never claimed serving the file is a vulnerability -
-- so the check carries no patched_in metadata. The mitigation is for
-- the operator to remove or deny the file at the web server / CDN
-- layer.
--
-- applies_to gates dispatch to detected Drupal hosts so the probe
-- does not waste a request on non-Drupal targets. The check claims
-- the host root before probing so a crawl of many pages on one
-- Drupal site issues exactly one GET against /CHANGELOG.txt.

local check = {
  name        = "drupal-changelog-disclosure",
  level       = "passive",
  scope       = "host",
  cwe         = "CWE-200",
  owasp       = "A05:2021 Security Misconfiguration",
  remediation = "Remove /CHANGELOG.txt from the document root, or deny it at the web server (nginx: location = /CHANGELOG.txt { deny all; }) or CDN. Drupal 8+ no longer ships the file by default; legacy Drupal 7 deployments should clean it up as part of hardening.",
  tier        = "passive",
  applies_to  = { cms = {"drupal"} },
}

local BODY_CAP = 4 * 1024

-- match_version returns the version string the CHANGELOG.txt leading
-- "Drupal x.y.z[, date]" line discloses, or "" when the body does
-- not look like a Drupal CHANGELOG (a generic 200-page response with
-- an arbitrary text/plain body should not be a false positive). The
-- match is anchored at the start of the trimmed body so a marketing
-- page that happens to contain the substring "Drupal 7" elsewhere
-- does not trip the check.
local function match_version(body)
  if body == nil or body == "" then return "" end
  local trimmed = body:gsub("^%s+", "")
  -- Drupal core CHANGELOG entries always start with the literal
  -- "Drupal " token, then a version, optionally followed by ", date".
  local version = trimmed:match("^Drupal%s+([%d][%d%.]*)")
  if version == nil then return "" end
  return version
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  local host_root = u.scheme .. "://" .. u.host
  if not ctx.scope:allows(host_root) then return nil end
  if not ctx.host.claim_once(host_root) then return nil end

  local probe_url = host_root .. "/CHANGELOG.txt"

  local req, mut_err = ctx.client:new_request{ method = "GET", url = probe_url }
  if mut_err then return nil, "drupal-changelog-disclosure: " .. mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, "drupal-changelog-disclosure: " .. do_err end

  if resp:status() ~= 200 then return nil end

  local body, _, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, "drupal-changelog-disclosure: " .. rerr end

  local version = match_version(body)
  if version == "" then return nil end

  return {
    {
      severity    = ctx.severity.low,
      target      = host_root,
      url         = probe_url,
      title       = "Drupal CHANGELOG.txt disclosed (version " .. version .. ")",
      detail      = string.format(
        "GET %s returned a Drupal core CHANGELOG file disclosing version %s. An attacker reading this file knows the exact build the site is running and can pick targeted exploits for it rather than fingerprinting through trial and error.",
        probe_url, version),
      evidence = ctx.evidence.build{
        method  = "GET",
        url     = probe_url,
        status  = resp:status(),
        headers = resp:headers(),
        body    = body,
      },
      dedupe_parts = { "drupal-changelog-disclosure" },
    },
  }
end

return check
