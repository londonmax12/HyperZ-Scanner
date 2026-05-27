-- crlf-injection: probes query / form sinks for CR/LF header
-- injection (HTTP response splitting, CWE-113). The payload embeds a
-- uniquely-named header (X-Hyperz-CRLF) carrying a fresh canary; if
-- that header appears on the parsed response, the server must have
-- decoded the request bytes and rendered the CR/LF into the response
-- stream verbatim.
--
-- Only LocQuery and LocForm sinks are probed - net/http rejects
-- CR/LF in outbound header values, so header / cookie sinks cannot
-- carry the payload from this client.

local check = {
  name        = "crlf-injection",
  level       = "default",
  scope       = "param",
  cwe         = "CWE-113",
  owasp       = "A03:2021 Injection",
  remediation = "Reject or strip CR (\\r) and LF (\\n) bytes from any value that flows into a response header (Location, Set-Cookie, custom headers). "
                .. "Prefer the framework's typed setters that perform this validation automatically rather than concatenating raw strings into the header stream. "
                .. "At the edge, configure the reverse proxy / WAF to drop responses whose header section contains unexpected line terminators.",
}

local CANARY_HEADER = "X-Hyperz-CRLF"
local BODY_CAP      = 4 * 1024

-- Full CRLF first (textbook), then LF-only and CR-only to catch
-- filters that strip one byte but not the other; aggressive scans add
-- the multi-byte aliasing trick.
local function variants(ctx)
  local v = { "\r\n", "\n", "\r" }
  if ctx:level_at_least("aggressive") then
    -- U+560A / U+560D have low bytes 0x0A / 0x0D; legacy Tomcat /
    -- Java decoders historically truncated multi-byte chars to their
    -- low byte and folded these into LF/CR.
    v[#v + 1] = "\xe5\x98\x8a\xe5\x98\x8d"
  end
  return v
end

local function sep_label(sep)
  if sep == "\r\n" then return "CRLF (\\r\\n)" end
  if sep == "\n"   then return "LF only (\\n)" end
  if sep == "\r"   then return "CR only (\\r)" end
  -- Hex-print anything else (aggressive multi-byte variant) so the
  -- finding text stays printable and the reader sees which exact
  -- byte sequence bypassed the filter.
  local parts = {}
  for i = 1, #sep do
    parts[#parts + 1] = string.format("U+%04X", string.byte(sep, i))
  end
  return table.concat(parts, " ")
end

local function new_canary()
  local hex = "0123456789abcdef"
  local out = { "hpzc" }
  for _ = 1, 12 do
    local r = math.random(1, 16)
    out[#out + 1] = string.sub(hex, r, r)
  end
  return table.concat(out)
end

local function probe(ctx, sink, sep)
  local canary  = new_canary()
  local payload = "hyperz" .. sep .. CANARY_HEADER .. ": " .. canary
  local req, mut_err = sink:mutate_request(payload)
  if mut_err then return nil, mut_err end

  local resp, do_err = ctx.client:do_no_follow(req)
  if do_err then return nil, do_err end

  local got = resp:headers():get(CANARY_HEADER)
  if got ~= canary then return nil end

  local body, truncated, rerr = resp:read_body_capped(BODY_CAP)
  if rerr then return nil, rerr end

  local probe_url = req:url()
  return {
    severity = ctx.severity.high,
    url      = probe_url,
    title    = string.format('CRLF header injection via %s "%s"', sink.loc, sink.name),
    detail   = string.format(
      'Parameter %q (%s) is reflected into a response header without filtering CR/LF bytes. '
        .. 'The probe injected %s into the value and the parsed response carried %s: %s, '
        .. 'proving the server wrote a fresh header line from attacker-controlled input. '
        .. 'This enables HTTP response splitting: an attacker can append arbitrary headers (Set-Cookie for session fixation, cache-control for poisoning) or a full second response body for stored XSS via downstream caches.',
      sink.name, sink.loc, sep_label(sep), CANARY_HEADER, got),
    evidence = ctx.evidence.from_exchange {
      request   = req,
      response  = resp,
      body      = body,
      truncated = truncated,
    },
    dedupe_parts = { "loc:" .. sink.loc, "param:" .. sink.name },
  }
end

function check.run(ctx)
  local u, perr = ctx.url.parse(ctx.page.url)
  if perr or not u or u.scheme == "" or u.host == "" then return nil end
  if not ctx.scope:allows(ctx.page.url) then return nil end

  local sinks = ctx.sinks.for_page{}
  if #sinks == 0 then return nil end
  local seps = variants(ctx)

  local findings = {}
  local seen = {}
  local first_err
  for _, sink in ipairs(sinks) do
    if sink.loc == ctx.locs.query or sink.loc == ctx.locs.form then
      if ctx.scope:allows(sink.url) then
        local found
        local probe_err
        for _, sep in ipairs(seps) do
          local f, e = probe(ctx, sink, sep)
          if e then probe_err = e; break end
          if f then found = f; break end
        end
        if probe_err then
          ctx:report(string.format("probe param %q (%s): %s", sink.name, sink.loc, probe_err))
          if not first_err then first_err = probe_err end
        elseif found then
          local key = "loc:" .. sink.loc .. "|param:" .. sink.name
          if not seen[key] then
            seen[key] = true
            findings[#findings + 1] = found
          end
        end
      end
    end
  end

  if first_err and #findings == 0 then return nil, first_err end
  return findings
end

return check
