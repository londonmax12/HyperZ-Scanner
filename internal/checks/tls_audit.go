package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

// TLSAudit performs a single, passive TLS handshake against the target host
// and reports on the negotiated protocol version, leaf certificate validity
// window, and hostname coverage. It issues no HTTP request.
type TLSAudit struct{}

func (TLSAudit) Name() string { return "tls-audit" }

func (TLSAudit) Level() Level { return LevelPassive }

// Expiry warning bands. Already-expired certs are High; "act now" is Medium
// inside two weeks; "schedule a rotation" is Low inside a month.
const (
	tlsExpiryUrgentWindow = 14 * 24 * time.Hour
	tlsExpirySoonWindow   = 30 * 24 * time.Hour
	tlsDialTimeout        = 10 * time.Second
)

// tlsAuditDial is indirected so tests can intercept the network dial and
// inject a controlled ConnectionState without spinning up a TLS server.
var tlsAuditDial = func(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: tlsDialTimeout}
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

// tlsAuditNow lets tests freeze "now" when evaluating expiry windows.
var tlsAuditNow = time.Now

func (c TLSAudit) Run(ctx context.Context, _ *httpclient.Client, _ *scope.Scope, p page.Page) ([]Finding, error) {
	target := p.URL
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	// http:// is a valid scan input but has no TLS to inspect. Return cleanly
	// emitting "no TLS" findings here would be noise; the missing-HSTS
	// finding from security-headers is a more useful signal.
	if u.Scheme != "https" {
		return nil, nil
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("target missing host: %s", target)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	// MinVersion: TLS 1.0 so we can *observe* obsolete servers rather than
	// failing the handshake closed. InsecureSkipVerify lets the handshake
	// complete on expired / self-signed / wrong-name certs so we can still
	// report what's there. ServerName drives SNI and matches what a normal
	// client would send.
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	conn, err := tlsAuditDial(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	var findings []Finding
	findings = append(findings, c.versionFinding(target, state.Version)...)

	if len(state.PeerCertificates) == 0 {
		findings = append(findings, Finding{
			Check:       c.Name(),
			Target:      target,
			URL:         target,
			Severity:    SeverityMedium,
			Title:       "TLS handshake completed without a server certificate",
			Detail:      fmt.Sprintf("%s presented no peer certificate", addr),
			CWE:         "CWE-295",
			OWASP:       "A02:2021 Cryptographic Failures",
			Remediation: "Configure the server to present a certificate chain that begins with a valid leaf certificate for the requested hostname.",
			DedupeKey:   MakeKey(c.Name(), ScopeHost, target, "no-cert"),
		})
		return findings, nil
	}
	leaf := state.PeerCertificates[0]
	findings = append(findings, c.expiryFindings(target, leaf)...)
	if f, ok := c.hostnameFinding(target, host, leaf); ok {
		findings = append(findings, f)
	}
	return findings, nil
}

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
		Check:       c.Name(),
		Target:      target,
		URL:         target,
		Severity:    severity,
		Title:       "obsolete TLS version negotiated: " + name,
		Detail:      fmt.Sprintf("server negotiated %s; modern clients require TLS 1.2 or later", name),
		CWE:         "CWE-327",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Disable TLS 1.1 and below; allow only TLS 1.2 and TLS 1.3 with modern cipher suites.",
		DedupeKey:   MakeKey(c.Name(), ScopeHost, target, "version:"+name),
	}}
}

func (c TLSAudit) expiryFindings(target string, leaf *x509.Certificate) []Finding {
	now := tlsAuditNow()
	cn := leaf.Subject.CommonName
	if now.After(leaf.NotAfter) {
		return []Finding{{
			Check:       c.Name(),
			Target:      target,
			URL:         target,
			Severity:    SeverityHigh,
			Title:       "TLS certificate has expired",
			Detail:      fmt.Sprintf("leaf certificate (CN=%s) expired on %s", cn, leaf.NotAfter.UTC().Format(time.RFC3339)),
			CWE:         "CWE-298",
			OWASP:       "A02:2021 Cryptographic Failures",
			Remediation: "Renew the certificate immediately and automate renewal (e.g., ACME / Let's Encrypt) to prevent recurrence.",
			DedupeKey:   MakeKey(c.Name(), ScopeHost, target, "cert-expired"),
		}}
	}
	if now.Before(leaf.NotBefore) {
		return []Finding{{
			Check:       c.Name(),
			Target:      target,
			URL:         target,
			Severity:    SeverityHigh,
			Title:       "TLS certificate is not yet valid",
			Detail:      fmt.Sprintf("leaf certificate (CN=%s) becomes valid at %s", cn, leaf.NotBefore.UTC().Format(time.RFC3339)),
			CWE:         "CWE-298",
			OWASP:       "A02:2021 Cryptographic Failures",
			Remediation: "Verify the server clock is correct, or reissue the certificate if its NotBefore was set in the future by mistake.",
			DedupeKey:   MakeKey(c.Name(), ScopeHost, target, "cert-not-yet-valid"),
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
		Check:       c.Name(),
		Target:      target,
		URL:         target,
		Severity:    severity,
		Title:       fmt.Sprintf("TLS certificate expires in %d days", days),
		Detail:      fmt.Sprintf("leaf certificate (CN=%s) expires on %s - within %s", cn, leaf.NotAfter.UTC().Format(time.RFC3339), window),
		CWE:         "CWE-298",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Renew the certificate ahead of expiry and verify automated renewal jobs are healthy.",
		// Day count drifts each run; key off scope so repeated runs collapse.
		DedupeKey: MakeKey(c.Name(), ScopeHost, target, "cert-expiry-soon"),
	}}
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
		Check:       c.Name(),
		Target:      target,
		URL:         target,
		Severity:    SeverityHigh,
		Title:       "TLS certificate hostname mismatch",
		Detail:      detail,
		CWE:         "CWE-297",
		OWASP:       "A02:2021 Cryptographic Failures",
		Remediation: "Reissue the certificate with the correct Subject Alternative Names, or route traffic to a host the existing certificate covers.",
		DedupeKey:   MakeKey(c.Name(), ScopeHost, target, "hostname-mismatch"),
	}, true
}
