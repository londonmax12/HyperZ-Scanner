package crypto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"strings"
	"time"
)

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
