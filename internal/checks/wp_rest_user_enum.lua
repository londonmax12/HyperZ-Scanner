-- wp-rest-user-enum: flags WordPress installs that expose user
-- objects via /wp-json/wp/v2/users to anonymous requests. The endpoint
-- returns a JSON array of user records (id, name, slug, ...) that an
-- attacker uses to build a valid-login list for credential stuffing,
-- targeted password reset abuse, or phishing.
--
-- WordPress does not consider this a vulnerability and has not patched
-- it: the endpoint is intentionally readable so themes can render
-- author profile pages. The check therefore carries no patched_in
-- metadata; it surfaces a misconfiguration that operators have to fix
-- by gating the route at the application layer (security plugins,
-- custom permission_callback) or at the edge (WAF rule, CDN auth).
--
-- applies_to gates to detected WordPress hosts so the probe does not
-- hit non-WP targets that happen to have a /wp-json/ path. The check
-- claims the host root before probing so a crawl that yields many
-- pages on one WP site triggers exactly one HTTP request.

local check = {
  name        = "wp-rest-user-enum",
  level       = "default",
  scope       = "host",
  cwe         = "CWE-200",
  owasp       = "A01:2021 Broken Access Control",
  remediation = "Restrict /wp-json/wp/v2/users to authenticated requests via a security plugin (Wordfence, iThemes Security) or a custom permission_callback on the route. Sites that do not need the endpoint should disable it entirely.",
  applies_to  = { cms = {"wordpress"} },
}

local BODY_CAP = 32 * 1024

-- looks_like_user_array confirms doc is a JSON array of objects that
-- each carry id + slug (the marker fields WordPress emits even when
-- the rest of the user object is filtered for unauthenticated reads).
-- A non-table doc, an empty table, or an entry without those fields
-- fails the check so a generic /wp-json/* handler that happens to
-- return an array does not produce a false positive.
local function looks_like_user_array(doc)
  if type(doc) ~= "table" then return false end
  if #doc == 0 then return false end
  for i = 1, #doc do
    local entry = doc[i]
    if type(entry) ~= "table" then return false end
    if entry.id == nil or entry.slug == nil then return false end
  end
  return true
end

-- collect_slugs returns up to cap user slugs from doc so the finding
-- detail can name the disclosed identifiers without dumping the whole
-- response. Capped to keep evidence snippets bounded on sites with
-- hundreds of authors.
local function collect_slugs(doc, cap)
  local out = {}
  for i = 1, math.min(#doc, cap) do
    local entry = doc[i]
    if type(entry) == "table" and type(entry.slug) == "string" then
      out[#out + 1] = entry.slug
    end
  end
  return out
end

-- all_slugs returns every string slug from doc, in document order, no
-- cap. Used by the discovery emission path so downstream checks (XSS,
-- SQLi, IDOR on profile fields) reach every disclosed author profile,
-- not just the truncated subset that appears in the finding detail.
-- The worklist's host budget is the only ceiling on how many emissions
-- land.
local function all_slugs(doc)
  local out = {}
  for i = 1, #doc do
    local entry = doc[i]
    if type(entry) == "table" and type(entry.slug) == "string" and entry.slug ~= "" then
      out[#out + 1] = entry.slug
    end
  end
  return out
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or u == nil or u.scheme == "" or u.host == "" then return nil end
  local host_root = u.scheme .. "://" .. u.host
  if not ctx.scope:allows(host_root) then return nil end
  if not ctx.host.claim_once(host_root) then return nil end

  local probe_url = host_root .. "/wp-json/wp/v2/users"

  local req, mut_err = ctx.client:new_request{ method = "GET", url = probe_url }
  if mut_err then return nil, "wp-rest-user-enum: " .. mut_err end
  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, "wp-rest-user-enum: " .. do_err end

  if resp:status() ~= 200 then return nil end

  local ct = resp:headers():get("Content-Type") or ""
  if ct:lower():find("application/json", 1, true) == nil then return nil end

  local body, _, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, "wp-rest-user-enum: " .. rerr end

  local doc = ctx.json.decode(body)
  if not looks_like_user_array(doc) then return nil end

  local count = #doc
  local slugs = collect_slugs(doc, 8)
  local slug_line = ""
  if #slugs > 0 then
    slug_line = " Disclosed slugs include: " .. table.concat(slugs, ", ")
    if count > #slugs then
      slug_line = slug_line .. string.format(" (+%d more).", count - #slugs)
    else
      slug_line = slug_line .. "."
    end
  end

  -- Emit each disclosed author's public profile page as a follow-on
  -- KindPage discovery so the rest of the check catalog (reflected
  -- XSS on profile fields, open-redirect on bio links, content
  -- discovery on author archive sub-paths) probes them automatically.
  -- The worklist deduplicates by canonical key, applies scope, and
  -- caps total per-host pushes via WithHostBudget, so a site with
  -- many authors is bounded on both axes.
  for _, slug in ipairs(all_slugs(doc)) do
    ctx:discover{ kind = "page", url = host_root .. "/author/" .. slug .. "/" }
  end

  return {
    {
      severity    = ctx.severity.medium,
      target      = host_root,
      url         = probe_url,
      title       = "WordPress REST API exposes user list to anonymous requests",
      detail      = string.format(
        "GET %s returned %d user object(s) without authentication. Each entry includes the user id, name, and slug, giving an attacker valid login names for credential stuffing or targeted phishing.%s",
        probe_url, count, slug_line),
      evidence = ctx.evidence.build{
        method  = "GET",
        url     = probe_url,
        status  = resp:status(),
        headers = resp:headers(),
        body    = body,
      },
      dedupe_parts = { "wp-rest-user-enum" },
    },
  }
end

return check
