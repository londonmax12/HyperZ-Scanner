package lua_engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSAudit performs a single, passive TLS handshake against the target host
// and reports on the negotiated protocol version, negotiated cipher suite,
// OCSP stapling presence, SCT (Certificate Transparency) presence, the
// validity windows of every certificate in the chain, and hostname
// coverage. It issues no HTTP request.
type TLSAudit struct{}

// Expiry warning bands. Already-expired certs are High; "act now" is Medium
// inside two weeks; "schedule a rotation" is Low inside a month.
const (
	tlsExpiryUrgentWindow = 14 * 24 * time.Hour
	tlsExpirySoonWindow   = 30 * 24 * time.Hour
	tlsDialTimeout        = 10 * time.Second
)

// sctExtensionOID is the X.509 extension carrying embedded Signed
// Certificate Timestamps (RFC 6962 section 3.3). Public CAs embed SCTs
// here so CT compliance survives even when the TLS terminator does not
// deliver them over the handshake extension or stapled OCSP response.
var sctExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// tlsAuditDial is indirected so tests can intercept the network dial and
// inject a controlled ConnectionState without spinning up a TLS server.
var tlsAuditDial = func(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: tlsDialTimeout}
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

// tlsAuditNow lets tests freeze "now" when evaluating expiry windows.
var tlsAuditNow = time.Now

func (c TLSAudit) versionFinding(target string, version uint16) []Finding {
	var severity Severity
	var name string
	switch version {
	case tls.VersionSSL30:
		severity, name = SeverityHigh, "SSL 3.0"
	case tls.VersionTLS10:
		severity, name = SeverityHigh, "TLS 1.0"
	case tls.VersionTLS11:
		severity, name = SeverityMedium, "TLS 1.1"
	default:
		// TLS 1.2 / 1.3 (or any future version) is acceptable; emit nothing.
		return nil
	}
	return []Finding{{
		Check:       "tls-audit",
		Target:      target,
		URL:         target,
		Severity:    severity,
		Title:       "obsolete TLS version negotiated: " + name,
		Detail:      fmt.Sprintf("server negotiated %s; modern clients require TLS 1.2 or later", name),
		CWE:         "CWE-327",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Disable TLS 1.1 and below; allow only TLS 1.2 and TLS 1.3 with modern cipher suites.",
		DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "version:"+name),
	}}
}

// cipherFinding flags negotiated cipher suites that Go's standard library
// classifies as insecure (RC4, 3DES, CBC-only, RSA key exchange without
// forward secrecy). Severity is High for the worst offenders (RC4, 3DES,
// NULL, EXPORT, anonymous) and Medium for everything else. TLS 1.3 cipher
// suites are all acceptable and never appear in InsecureCipherSuites().
func (c TLSAudit) cipherFinding(target string, suite uint16) []Finding {
	if !isInsecureCipher(suite) {
		return nil
	}
	name := tls.CipherSuiteName(suite)
	severity := SeverityMedium
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "RC4"),
		strings.Contains(upper, "3DES"),
		strings.Contains(upper, "_DES_"),
		strings.Contains(upper, "NULL"),
		strings.Contains(upper, "EXPORT"),
		strings.Contains(upper, "ANON"):
		severity = SeverityHigh
	}
	return []Finding{{
		Check:       "tls-audit",
		Target:      target,
		URL:         target,
		Severity:    severity,
		Title:       "weak TLS cipher suite negotiated: " + name,
		Detail:      fmt.Sprintf("server selected %s; this suite is considered insecure (no forward secrecy, RC4/3DES, CBC, or similar weakness)", name),
		CWE:         "CWE-327",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Restrict the server cipher list to AEAD suites with forward secrecy (TLS_AES_*_GCM, TLS_CHACHA20_POLY1305, TLS_ECDHE_*_GCM, TLS_ECDHE_*_CHACHA20).",
		DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "weak-cipher", name),
	}}
}

// isInsecureCipher classifies a negotiated cipher suite by name rather
// than by tls.InsecureCipherSuites() alone. The stdlib's list omits the
// CBC-SHA1 ECDHE suites that modern guidance still flags (Lucky13,
// generic padding-oracle exposure), so name-substring matching picks up
// the broader weak set: any CBC mode, RC4, 3DES/DES, NULL, EXPORT,
// anonymous, or static-RSA (no forward secrecy). TLS 1.3 AEAD suites
// (AES_GCM, CHACHA20_POLY1305) contain none of these tokens and pass.
func isInsecureCipher(id uint16) bool {
	upper := strings.ToUpper(tls.CipherSuiteName(id))
	switch {
	case strings.Contains(upper, "RC4"),
		strings.Contains(upper, "3DES"),
		strings.Contains(upper, "_DES_"),
		strings.Contains(upper, "NULL"),
		strings.Contains(upper, "EXPORT"),
		strings.Contains(upper, "ANON"),
		strings.Contains(upper, "_CBC_"),
		strings.HasPrefix(upper, "TLS_RSA_WITH_"):
		return true
	}
	return false
}

func (c TLSAudit) expiryFindings(target string, leaf *x509.Certificate) []Finding {
	now := tlsAuditNow()
	cn := leaf.Subject.CommonName
	if now.After(leaf.NotAfter) {
		return []Finding{{
			Check:       "tls-audit",
			Target:      target,
			URL:         target,
			Severity:    SeverityHigh,
			Title:       "TLS certificate has expired",
			Detail:      fmt.Sprintf("leaf certificate (CN=%s) expired on %s", cn, leaf.NotAfter.UTC().Format(time.RFC3339)),
			CWE:         "CWE-298",
			OWASP:       "A02:2021 Cryptographic Failures",
			Remediation: "Renew the certificate immediately and automate renewal (e.g., ACME / Let's Encrypt) to prevent recurrence.",
			DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "cert-expired"),
		}}
	}
	if now.Before(leaf.NotBefore) {
		return []Finding{{
			Check:       "tls-audit",
			Target:      target,
			URL:         target,
			Severity:    SeverityHigh,
			Title:       "TLS certificate is not yet valid",
			Detail:      fmt.Sprintf("leaf certificate (CN=%s) becomes valid at %s", cn, leaf.NotBefore.UTC().Format(time.RFC3339)),
			CWE:         "CWE-298",
			OWASP:       "A02:2021 Cryptographic Failures",
			Remediation: "Verify the server clock is correct, or reissue the certificate if its NotBefore was set in the future by mistake.",
			DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "cert-not-yet-valid"),
		}}
	}
	until := leaf.NotAfter.Sub(now)
	var severity Severity
	var window string
	switch {
	case until < tlsExpiryUrgentWindow:
		severity, window = SeverityMedium, "14 days"
	case until < tlsExpirySoonWindow:
		severity, window = SeverityLow, "30 days"
	default:
		return nil
	}
	days := int(until / (24 * time.Hour))
	return []Finding{{
		Check:       "tls-audit",
		Target:      target,
		URL:         target,
		Severity:    severity,
		Title:       fmt.Sprintf("TLS certificate expires in %d days", days),
		Detail:      fmt.Sprintf("leaf certificate (CN=%s) expires on %s - within %s", cn, leaf.NotAfter.UTC().Format(time.RFC3339), window),
		CWE:         "CWE-298",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Renew the certificate ahead of expiry and verify automated renewal jobs are healthy.",
		// Day count drifts each run; key off scope so repeated runs collapse.
		DedupeKey: MakeKey("tls-audit", ScopeHost, target, "cert-expiry-soon"),
	}}
}

// intermediateExpiryFindings walks PeerCertificates[1:] and applies the
// same three-band expiry test as the leaf check. CAs rotate intermediates
// independently of leaves and on tighter schedules, so an intermediate
// that expires next week is a separate operational signal from a healthy
// leaf chained off it. Findings are dedupe-keyed by chain position so
// repeated runs collapse rather than fanning out on day-count drift.
func (c TLSAudit) intermediateExpiryFindings(target string, intermediates []*x509.Certificate) []Finding {
	now := tlsAuditNow()
	var out []Finding
	for i, cert := range intermediates {
		role := fmt.Sprintf("intermediate #%d", i+1)
		cn := cert.Subject.CommonName
		posPart := fmt.Sprintf("pos=%d", i+1)
		if now.After(cert.NotAfter) {
			out = append(out, Finding{
				Check:       "tls-audit",
				Target:      target,
				URL:         target,
				Severity:    SeverityHigh,
				Title:       "TLS chain " + role + " certificate has expired",
				Detail:      fmt.Sprintf("%s certificate (CN=%s) expired on %s", role, cn, cert.NotAfter.UTC().Format(time.RFC3339)),
				CWE:         "CWE-298",
				OWASP:       "A02:2021 Cryptographic Failures",
				Remediation: "Refresh the chain bundle from the issuing CA so an unexpired intermediate is presented in the handshake.",
				DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "chain-expired", posPart),
			})
			continue
		}
		if now.Before(cert.NotBefore) {
			out = append(out, Finding{
				Check:       "tls-audit",
				Target:      target,
				URL:         target,
				Severity:    SeverityHigh,
				Title:       "TLS chain " + role + " certificate is not yet valid",
				Detail:      fmt.Sprintf("%s certificate (CN=%s) becomes valid at %s", role, cn, cert.NotBefore.UTC().Format(time.RFC3339)),
				CWE:         "CWE-298",
				OWASP:       "A02:2021 Cryptographic Failures",
				Remediation: "Verify the server clock is correct, or rebuild the chain with an intermediate that is already valid.",
				DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "chain-not-yet-valid", posPart),
			})
			continue
		}
		until := cert.NotAfter.Sub(now)
		var severity Severity
		var window string
		switch {
		case until < tlsExpiryUrgentWindow:
			severity, window = SeverityMedium, "14 days"
		case until < tlsExpirySoonWindow:
			severity, window = SeverityLow, "30 days"
		default:
			continue
		}
		days := int(until / (24 * time.Hour))
		out = append(out, Finding{
			Check:       "tls-audit",
			Target:      target,
			URL:         target,
			Severity:    severity,
			Title:       fmt.Sprintf("TLS chain %s expires in %d days", role, days),
			Detail:      fmt.Sprintf("%s certificate (CN=%s) expires on %s - within %s", role, cn, cert.NotAfter.UTC().Format(time.RFC3339), window),
			CWE:         "CWE-298",
			OWASP:       "A02:2021 Cryptographic Failures",
			Remediation: "Refresh the chain bundle from the issuing CA before the intermediate expires.",
			DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "chain-expiry-soon", posPart),
		})
	}
	return out
}

// ocspStapleFinding flags handshakes the server did not staple an OCSP
// response onto. Stapling avoids a third-party CA round-trip on every
// connection and the privacy leak that comes with it; without it,
// clients either fall back to direct OCSP fetches (slow, often soft-
// fail) or skip revocation checks entirely. If the leaf cert carries
// the OCSP-Must-Staple TLS-feature extension (RFC 7633), a missing
// staple is a hard trust failure for compliant clients.
func (c TLSAudit) ocspStapleFinding(target string, ocsp []byte) []Finding {
	if len(ocsp) > 0 {
		return nil
	}
	return []Finding{{
		Check:       "tls-audit",
		Target:      target,
		URL:         target,
		Severity:    SeverityLow,
		Title:       "TLS handshake did not include a stapled OCSP response",
		Detail:      "the server returned no OCSP response in the handshake; clients must perform their own revocation checks (or skip them entirely)",
		CWE:         "CWE-299",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Enable OCSP stapling at the TLS terminator (nginx ssl_stapling, Apache SSLUseStapling, or the equivalent on your CDN / load balancer) so revocation status rides with the handshake.",
		DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "no-ocsp-staple"),
	}}
}

// sctFinding flags leaves that carry no Signed Certificate Timestamps,
// either via the TLS handshake extension (RFC 6962 section 3.3.1) or
// embedded directly in the certificate (extension OID
// 1.3.6.1.4.1.11129.2.4.2). Browsers like Chrome require at least two
// SCTs from independent CT logs for a publicly-trusted cert; a cert
// with none will fail trust on those clients. Private / internal CAs
// legitimately produce SCT-less certs, so the severity is Low rather
// than Medium.
func (c TLSAudit) sctFinding(target string, leaf *x509.Certificate, handshakeSCTs [][]byte) []Finding {
	if hasNonEmptySCT(handshakeSCTs) {
		return nil
	}
	if leafEmbedsSCT(leaf) {
		return nil
	}
	return []Finding{{
		Check:       "tls-audit",
		Target:      target,
		URL:         target,
		Severity:    SeverityLow,
		Title:       "TLS leaf certificate carries no Signed Certificate Timestamps",
		Detail:      "the handshake exposed no SCT extension and the leaf certificate embeds none; Certificate-Transparency-enforcing clients may reject this certificate",
		CWE:         "CWE-295",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Issue the certificate from a CA that logs to public CT logs and embeds SCTs (every public CA today), or configure the TLS terminator to deliver SCTs via the handshake extension or a stapled OCSP response.",
		DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "no-sct"),
	}}
}

func hasNonEmptySCT(scts [][]byte) bool {
	for _, s := range scts {
		if len(s) > 0 {
			return true
		}
	}
	return false
}

func leafEmbedsSCT(leaf *x509.Certificate) bool {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(sctExtensionOID) && len(ext.Value) > 0 {
			return true
		}
	}
	return false
}

func (c TLSAudit) hostnameFinding(target, host string, leaf *x509.Certificate) (Finding, bool) {
	if leaf.VerifyHostname(host) == nil {
		return Finding{}, false
	}
	covers := leaf.DNSNames
	if len(covers) == 0 && leaf.Subject.CommonName != "" {
		covers = []string{leaf.Subject.CommonName}
	}
	detail := fmt.Sprintf("requested %s, but certificate is valid for %s", host, strings.Join(covers, ", "))
	if len(covers) == 0 {
		detail = fmt.Sprintf("requested %s, but certificate carries no hostnames", host)
	}
	return Finding{
		Check:       "tls-audit",
		Target:      target,
		URL:         target,
		Severity:    SeverityHigh,
		Title:       "TLS certificate hostname mismatch",
		Detail:      detail,
		CWE:         "CWE-297",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Reissue the certificate with the correct Subject Alternative Names, or route traffic to a host the existing certificate covers.",
		DedupeKey:   MakeKey("tls-audit", ScopeHost, target, "hostname-mismatch"),
	}, true
}
