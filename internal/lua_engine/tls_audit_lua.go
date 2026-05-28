package lua_engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"
)

// This file exposes the tls-audit check's helpers to the Lua bridge.
// Sibling to tls_audit.go: forwards into the package-private timing
// knobs, the dialer indirection, and the cipher / SCT classifiers so
// the Lua port matches the Go check 1:1.

// SetTLSAuditNowForTest swaps the package-level tlsAuditNow indirection
// so the checks_lua parity tests can freeze "now" for both
// implementations from outside the checks package. Mirrors the
// withFrozenNow helper used inside the package's own tests.
func SetTLSAuditNowForTest(now time.Time) (restore func()) {
	prev := tlsAuditNow
	tlsAuditNow = func() time.Time { return now }
	return func() { tlsAuditNow = prev }
}

// SetTLSAuditDialForTest swaps the package-level tlsAuditDial
// indirection so the bridge surface can route through a synthetic
// dialer in tests that need a mocked ConnectionState (none today, but
// the seam is here for the same reason as the now setter - parity
// tests should not need to reach into private state).
func SetTLSAuditDialForTest(dial func(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error)) (restore func()) {
	prev := tlsAuditDial
	tlsAuditDial = dial
	return func() { tlsAuditDial = prev }
}

// TLSAuditExpiryUrgentWindowSeconds / TLSAuditExpirySoonWindowSeconds /
// TLSAuditDialTimeoutSeconds expose the per-check timing knobs so the
// Lua port computes the same "within 14 days" / "within 30 days" bands
// the Go check uses. Constants only - changing them is a Go-side
// decision the Lua port follows.
func TLSAuditExpiryUrgentWindowSeconds() int { return int(tlsExpiryUrgentWindow / time.Second) }
func TLSAuditExpirySoonWindowSeconds() int   { return int(tlsExpirySoonWindow / time.Second) }
func TLSAuditDialTimeoutSeconds() int        { return int(tlsDialTimeout / time.Second) }

// TLSAuditNowUnix returns the current time (post-injection) as Unix
// seconds. Bridge surfaces ctx.tls.now() on top of this so a frozen-
// now test on the Go side flips the Lua port's clock in lockstep.
func TLSAuditNowUnix() int64 { return tlsAuditNow().Unix() }

// TLSAuditVersionLabel returns the human-readable name of a negotiated
// TLS / SSL protocol version. Empty for modern (TLS 1.2 / 1.3) so the
// Lua port can decide "modern, emit nothing" with a single empty
// check. Names match the Go check's switch cases byte-for-byte.
func TLSAuditVersionLabel(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return ""
}

// TLSAuditCipherSuiteName wraps tls.CipherSuiteName so the Lua port
// reads the same canonical name strings the Go check stamps onto
// findings. Empty for unknown suite ids.
func TLSAuditCipherSuiteName(id uint16) string { return tls.CipherSuiteName(id) }

// TLSAuditIsInsecureCipher exposes the cipher-classification rule the
// Go check uses (name-substring scan over RC4 / 3DES / DES / NULL /
// EXPORT / ANON / _CBC_ / TLS_RSA_WITH_). The Lua port decides
// severity above this (HIGH for RC4/3DES/NULL/EXPORT/ANON, MEDIUM for
// CBC / static-RSA) using the same name string.
func TLSAuditIsInsecureCipher(id uint16) bool { return isInsecureCipher(id) }

// TLSAuditHandshakeResultLua is the per-handshake snapshot the Lua tls
// bridge hands back to the .lua port. Mirrors the load-bearing fields
// of tls.ConnectionState plus the SCT-extension flag for each peer
// cert; everything finding-shape (severity bands, dedupe-key parts,
// remediation text) is composed Lua-side.
type TLSAuditHandshakeResultLua struct {
	Version              uint16
	VersionLabel         string
	CipherSuite          uint16
	CipherSuiteName      string
	IsInsecureCipher     bool
	OCSPResponsePresent  bool
	HandshakeSCTNonEmpty bool
	PeerCertificates     []*x509.Certificate
}

// TLSAuditHandshakeLua performs the same single passive TLS handshake
// TLSAudit.Run does and returns the per-cert + per-connection fields
// the Lua port needs. Goes through the same tlsAuditDial indirection
// so tests can intercept; honors the host's SNI server name unless an
// override is passed.
func TLSAuditHandshakeLua(ctx context.Context, addr, serverName string) (*TLSAuditHandshakeResultLua, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	conn, err := tlsAuditDial(ctx, addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	out := &TLSAuditHandshakeResultLua{
		Version:              state.Version,
		VersionLabel:         TLSAuditVersionLabel(state.Version),
		CipherSuite:          state.CipherSuite,
		CipherSuiteName:      TLSAuditCipherSuiteName(state.CipherSuite),
		IsInsecureCipher:     TLSAuditIsInsecureCipher(state.CipherSuite),
		OCSPResponsePresent:  len(state.OCSPResponse) > 0,
		HandshakeSCTNonEmpty: hasNonEmptySCT(state.SignedCertificateTimestamps),
		PeerCertificates:     state.PeerCertificates,
	}
	return out, nil
}

// TLSAuditCertEmbedsSCT exposes leafEmbedsSCT. The Lua port falls back
// on this when the handshake delivered no SCTs - a publicly-trusted
// cert that embeds SCTs in the X509v3 extension still satisfies CT
// compliance.
func TLSAuditCertEmbedsSCT(cert *x509.Certificate) bool { return leafEmbedsSCT(cert) }

// TLSAuditCertVerifyHostname mirrors *x509.Certificate.VerifyHostname
// returning true when the cert covers host. Wrapped so the .lua port
// produces an ok-bool without each call site marshalling an error
// shape Lua would just throw away.
func TLSAuditCertVerifyHostname(cert *x509.Certificate, host string) bool {
	if cert == nil {
		return false
	}
	return cert.VerifyHostname(host) == nil
}
