-- tls-audit: performs a single, passive TLS handshake against the
-- target host and reports on the negotiated protocol version,
-- negotiated cipher suite, OCSP stapling, SCT (Certificate
-- Transparency) presence, the validity windows of every certificate
-- in the chain, and hostname coverage. Issues no HTTP request.
--
-- Detection logic lives here; the bridge owns the bytes-side concerns
-- (dialing the socket, parsing x509 extensions, computing the cipher
-- name + insecure-cipher classification). Every severity band,
-- finding shape, and dedupe-key part is composed in this file so a
-- Lua author can adjust the thresholds without leaving Lua.

local check = {
  name  = "tls-audit",
  level = "passive",
  scope = "host",
  owasp = "A02:2021 Cryptographic Failures",
  tier  = "fingerprint",
}

local function version_finding(ctx, target, version_name)
  local sev
  if version_name == "SSL 3.0" or version_name == "TLS 1.0" then
    sev = "high"
  elseif version_name == "TLS 1.1" then
    sev = "medium"
  else
    -- TLS 1.2 / 1.3 / unknown future versions: quiet.
    return nil
  end
  return {
    target      = target,
    url         = target,
    severity    = ctx.severity[sev],
    title       = "obsolete TLS version negotiated: " .. version_name,
    detail      = "server negotiated " .. version_name .. "; modern clients require TLS 1.2 or later",
    cwe         = "CWE-327",
    remediation = "Disable TLS 1.1 and below; allow only TLS 1.2 and TLS 1.3 with modern cipher suites.",
    dedupe_parts = { "version:" .. version_name },
  }
end

-- High when the cipher name contains one of the broken-by-default
-- tokens; medium for the rest of the insecure set (CBC, static-RSA).
local function cipher_severity(name)
  local upper = string.upper(name)
  if string.find(upper, "RC4", 1, true)
      or string.find(upper, "3DES", 1, true)
      or string.find(upper, "_DES_", 1, true)
      or string.find(upper, "NULL", 1, true)
      or string.find(upper, "EXPORT", 1, true)
      or string.find(upper, "ANON", 1, true) then
    return "high"
  end
  return "medium"
end

local function cipher_finding(ctx, target, state)
  if not state.is_insecure_cipher then return nil end
  local name = state.cipher_suite_name
  return {
    target      = target,
    url         = target,
    severity    = ctx.severity[cipher_severity(name)],
    title       = "weak TLS cipher suite negotiated: " .. name,
    detail      = "server selected " .. name .. "; this suite is considered insecure (no forward secrecy, RC4/3DES, CBC, or similar weakness)",
    cwe         = "CWE-327",
    remediation = "Restrict the server cipher list to AEAD suites with forward secrecy (TLS_AES_*_GCM, TLS_CHACHA20_POLY1305, TLS_ECDHE_*_GCM, TLS_ECDHE_*_CHACHA20).",
    dedupe_parts = { "weak-cipher", name },
  }
end


-- expiry_findings handles the leaf cert's three-band expiry test.
-- High for already-expired / not-yet-valid (clock skew or rotation
-- mistake); Medium for within 14 days; Low for within 30 days; quiet
-- when the cert is comfortably valid. Day count drifts each run so
-- the dedupe key keys off scope, not the day count.
local function expiry_findings(ctx, target, leaf)
  local now = ctx.tls.now()
  local cn = leaf:subject_cn()
  local not_after = leaf:not_after()
  local not_before = leaf:not_before()
  if now > not_after then
    return {{
      target      = target,
      url         = target,
      severity    = ctx.severity.high,
      title       = "TLS certificate has expired",
      detail      = string.format("leaf certificate (CN=%s) expired on %s", cn, ctx.tls.format_unix_rfc3339_utc(not_after)),
      cwe         = "CWE-298",
      remediation = "Renew the certificate immediately and automate renewal (e.g., ACME / Let's Encrypt) to prevent recurrence.",
      dedupe_parts = { "cert-expired" },
    }}
  end
  if now < not_before then
    return {{
      target      = target,
      url         = target,
      severity    = ctx.severity.high,
      title       = "TLS certificate is not yet valid",
      detail      = string.format("leaf certificate (CN=%s) becomes valid at %s", cn, ctx.tls.format_unix_rfc3339_utc(not_before)),
      cwe         = "CWE-298",
      remediation = "Verify the server clock is correct, or reissue the certificate if its NotBefore was set in the future by mistake.",
      dedupe_parts = { "cert-not-yet-valid" },
    }}
  end
  local until_secs = not_after - now
  local sev, window
  if until_secs < ctx.tls.expiry_urgent_window_s() then
    sev, window = "medium", "14 days"
  elseif until_secs < ctx.tls.expiry_soon_window_s() then
    sev, window = "low", "30 days"
  else
    return nil
  end
  local days = math.floor(until_secs / (24 * 3600))
  return {{
    target      = target,
    url         = target,
    severity    = ctx.severity[sev],
    title       = string.format("TLS certificate expires in %d days", days),
    detail      = string.format("leaf certificate (CN=%s) expires on %s - within %s", cn, ctx.tls.format_unix_rfc3339_utc(not_after), window),
    cwe         = "CWE-298",
    remediation = "Renew the certificate ahead of expiry and verify automated renewal jobs are healthy.",
    dedupe_parts = { "cert-expiry-soon" },
  }}
end

-- intermediate_expiry_findings repeats the leaf logic for every chain
-- intermediate (PeerCertificates[1:]). Findings carry a chain-position
-- dedupe-key part so the second intermediate expiring soon does not
-- collapse with the first one.
local function intermediate_expiry_findings(ctx, target, intermediates)
  local now = ctx.tls.now()
  local out = {}
  for i, cert in ipairs(intermediates) do
    local role = string.format("intermediate #%d", i)
    local cn = cert:subject_cn()
    local pos_part = string.format("pos=%d", i)
    local not_after = cert:not_after()
    local not_before = cert:not_before()
    if now > not_after then
      out[#out + 1] = {
        target      = target,
        url         = target,
        severity    = ctx.severity.high,
        title       = "TLS chain " .. role .. " certificate has expired",
        detail      = string.format("%s certificate (CN=%s) expired on %s", role, cn, ctx.tls.format_unix_rfc3339_utc(not_after)),
        cwe         = "CWE-298",
        remediation = "Refresh the chain bundle from the issuing CA so an unexpired intermediate is presented in the handshake.",
        dedupe_parts = { "chain-expired", pos_part },
      }
    elseif now < not_before then
      out[#out + 1] = {
        target      = target,
        url         = target,
        severity    = ctx.severity.high,
        title       = "TLS chain " .. role .. " certificate is not yet valid",
        detail      = string.format("%s certificate (CN=%s) becomes valid at %s", role, cn, ctx.tls.format_unix_rfc3339_utc(not_before)),
        cwe         = "CWE-298",
        remediation = "Verify the server clock is correct, or rebuild the chain with an intermediate that is already valid.",
        dedupe_parts = { "chain-not-yet-valid", pos_part },
      }
    else
      local until_secs = not_after - now
      local sev, window
      if until_secs < ctx.tls.expiry_urgent_window_s() then
        sev, window = "medium", "14 days"
      elseif until_secs < ctx.tls.expiry_soon_window_s() then
        sev, window = "low", "30 days"
      end
      if sev then
        local days = math.floor(until_secs / (24 * 3600))
        out[#out + 1] = {
          target      = target,
          url         = target,
          severity    = ctx.severity[sev],
          title       = string.format("TLS chain %s expires in %d days", role, days),
          detail      = string.format("%s certificate (CN=%s) expires on %s - within %s", role, cn, ctx.tls.format_unix_rfc3339_utc(not_after), window),
          cwe         = "CWE-298",
          remediation = "Refresh the chain bundle from the issuing CA before the intermediate expires.",
          dedupe_parts = { "chain-expiry-soon", pos_part },
        }
      end
    end
  end
  return out
end

local function ocsp_finding(ctx, target, state)
  if state.ocsp_response_present then return nil end
  return {
    target      = target,
    url         = target,
    severity    = ctx.severity.low,
    title       = "TLS handshake did not include a stapled OCSP response",
    detail      = "the server returned no OCSP response in the handshake; clients must perform their own revocation checks (or skip them entirely)",
    cwe         = "CWE-299",
    remediation = "Enable OCSP stapling at the TLS terminator (nginx ssl_stapling, Apache SSLUseStapling, or the equivalent on your CDN / load balancer) so revocation status rides with the handshake.",
    dedupe_parts = { "no-ocsp-staple" },
  }
end

local function sct_finding(ctx, target, leaf, state)
  if state.handshake_sct_nonempty then return nil end
  if leaf:has_embedded_sct() then return nil end
  return {
    target      = target,
    url         = target,
    severity    = ctx.severity.low,
    title       = "TLS leaf certificate carries no Signed Certificate Timestamps",
    detail      = "the handshake exposed no SCT extension and the leaf certificate embeds none; Certificate-Transparency-enforcing clients may reject this certificate",
    cwe         = "CWE-295",
    remediation = "Issue the certificate from a CA that logs to public CT logs and embeds SCTs (every public CA today), or configure the TLS terminator to deliver SCTs via the handshake extension or a stapled OCSP response.",
    dedupe_parts = { "no-sct" },
  }
end

local function hostname_finding(ctx, target, host, leaf)
  if leaf:verifies_hostname(host) then return nil end
  local covers = leaf:dns_names()
  if #covers == 0 then
    local cn = leaf:subject_cn()
    if cn ~= "" then covers = { cn } end
  end
  local detail
  if #covers == 0 then
    detail = string.format("requested %s, but certificate carries no hostnames", host)
  else
    detail = string.format("requested %s, but certificate is valid for %s", host, table.concat(covers, ", "))
  end
  return {
    target      = target,
    url         = target,
    severity    = ctx.severity.high,
    title       = "TLS certificate hostname mismatch",
    detail      = detail,
    cwe         = "CWE-297",
    remediation = "Reissue the certificate with the correct Subject Alternative Names, or route traffic to a host the existing certificate covers.",
    dedupe_parts = { "hostname-mismatch" },
  }
end

function check.run(ctx)
  local target = ctx.page.url
  local u, perr = ctx.url.parse(target)
  if perr then
    -- Unparseable URL surfaces as a check-level error, not a silent
    -- miss.
    return nil, perr
  end
  -- http:// has no TLS to inspect; security-headers covers the
  -- missing-HSTS angle. Quiet exit.
  if u.scheme ~= "https" then return nil end
  local host = u.hostname
  if host == "" then return nil, "target missing host: " .. target end
  local port = u.port
  if port == "" then port = "443" end
  local addr = host .. ":" .. port

  local state, herr = ctx.tls.handshake(addr, host)
  if herr then
    return nil, "tls dial " .. addr .. ": " .. herr
  end

  local findings = {}
  local f_v = version_finding(ctx, target, state.version_name)
  if f_v then findings[#findings + 1] = f_v end
  local f_c = cipher_finding(ctx, target, state)
  if f_c then findings[#findings + 1] = f_c end

  local certs = state.peer_certificates
  if #certs == 0 then
    findings[#findings + 1] = {
      target      = target,
      url         = target,
      severity    = ctx.severity.medium,
      title       = "TLS handshake completed without a server certificate",
      detail      = addr .. " presented no peer certificate",
      cwe         = "CWE-295",
      remediation = "Configure the server to present a certificate chain that begins with a valid leaf certificate for the requested hostname.",
      dedupe_parts = { "no-cert" },
    }
    return findings
  end

  local leaf = certs[1]
  for _, f in ipairs(expiry_findings(ctx, target, leaf) or {}) do
    findings[#findings + 1] = f
  end
  local intermediates = {}
  for i = 2, #certs do intermediates[#intermediates + 1] = certs[i] end
  for _, f in ipairs(intermediate_expiry_findings(ctx, target, intermediates)) do
    findings[#findings + 1] = f
  end
  local f_o = ocsp_finding(ctx, target, state)
  if f_o then findings[#findings + 1] = f_o end
  local f_s = sct_finding(ctx, target, leaf, state)
  if f_s then findings[#findings + 1] = f_s end
  local f_h = hostname_finding(ctx, target, host, leaf)
  if f_h then findings[#findings + 1] = f_h end

  return findings
end

return check
