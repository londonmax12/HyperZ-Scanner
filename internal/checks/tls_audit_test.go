package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/page"
)

func TestTLSAuditName(t *testing.T) {
	if got := (TLSAudit{}).Name(); got != "tls-audit" {
		t.Fatalf("Name = %q, want tls-audit", got)
	}
}

func TestTLSAuditLevel(t *testing.T) {
	if got := (TLSAudit{}).Level(); got != LevelPassive {
		t.Fatalf("Level = %v, want passive", got)
	}
}

func TestTLSAuditSkipsHTTP(t *testing.T) {
	// http:// is a valid scan input but has no TLS. The check must return
	// cleanly without dialing anything.
	findings, err := TLSAudit{}.Run(context.Background(), nil, nil, page.FromURL("http://example.com/"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on http://, got %d: %+v", len(findings), findings)
	}
}

func TestTLSAuditRejectsHostlessTarget(t *testing.T) {
	_, err := TLSAudit{}.Run(context.Background(), nil, nil, page.FromURL("https:///path"))
	if err == nil {
		t.Fatal("expected error for target with no host")
	}
}

func TestTLSAuditHappyPath(t *testing.T) {
	// httptest.NewTLSServer uses a long-lived cert (valid until 2084) for
	// 127.0.0.1/::1/example.com and negotiates TLS 1.3 with a strong
	// cipher. It does not staple OCSP and the cert has no SCTs, so those
	// two Low hardening findings are expected; nothing should rise to
	// Medium or above.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := TLSAudit{}.Run(context.Background(), nil, nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, f := range findings {
		if SeverityRank(f.Severity) >= SeverityRank(SeverityMedium) {
			t.Errorf("unexpected medium+ finding on modern HTTPS: %+v", f)
		}
	}
}

func TestTLSAuditVersionFindings(t *testing.T) {
	tests := []struct {
		name     string
		version  uint16
		want     int
		severity Severity
	}{
		{"TLS 1.3 quiet", tls.VersionTLS13, 0, ""},
		{"TLS 1.2 quiet", tls.VersionTLS12, 0, ""},
		{"TLS 1.1 medium", tls.VersionTLS11, 1, SeverityMedium},
		{"TLS 1.0 high", tls.VersionTLS10, 1, SeverityHigh},
		{"SSL 3.0 high", tls.VersionSSL30, 1, SeverityHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := TLSAudit{}.versionFinding("https://x", tt.version)
			if len(fs) != tt.want {
				t.Fatalf("got %d findings, want %d: %+v", len(fs), tt.want, fs)
			}
			if tt.want == 1 && fs[0].Severity != tt.severity {
				t.Errorf("severity = %q, want %q", fs[0].Severity, tt.severity)
			}
			if tt.want == 1 && fs[0].DedupeKey == "" {
				t.Errorf("DedupeKey empty")
			}
		})
	}
}

func TestTLSAuditExpiryExpired(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "example.com"},
		NotBefore: now.Add(-365 * 24 * time.Hour),
		NotAfter:  now.Add(-24 * time.Hour),
	}
	fs := TLSAudit{}.expiryFindings("https://x", leaf)
	if len(fs) != 1 || fs[0].Severity != SeverityHigh {
		t.Fatalf("want 1 high finding, got %+v", fs)
	}
	if !strings.Contains(fs[0].Title, "expired") {
		t.Errorf("title = %q, want it to mention expired", fs[0].Title)
	}
}

func TestTLSAuditExpiryNotYetValid(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "example.com"},
		NotBefore: now.Add(24 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
	}
	fs := TLSAudit{}.expiryFindings("https://x", leaf)
	if len(fs) != 1 || fs[0].Severity != SeverityHigh {
		t.Fatalf("want 1 high finding, got %+v", fs)
	}
	if !strings.Contains(fs[0].Title, "not yet valid") {
		t.Errorf("title = %q, want 'not yet valid'", fs[0].Title)
	}
}

func TestTLSAuditExpiryUrgentWindow(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "example.com"},
		NotBefore: now.Add(-30 * 24 * time.Hour),
		NotAfter:  now.Add(5 * 24 * time.Hour),
	}
	fs := TLSAudit{}.expiryFindings("https://x", leaf)
	if len(fs) != 1 || fs[0].Severity != SeverityMedium {
		t.Fatalf("want 1 medium finding (within 14d), got %+v", fs)
	}
}

func TestTLSAuditExpirySoonWindow(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "example.com"},
		NotBefore: now.Add(-30 * 24 * time.Hour),
		NotAfter:  now.Add(20 * 24 * time.Hour),
	}
	fs := TLSAudit{}.expiryFindings("https://x", leaf)
	if len(fs) != 1 || fs[0].Severity != SeverityLow {
		t.Fatalf("want 1 low finding (within 30d), got %+v", fs)
	}
}

func TestTLSAuditExpiryHealthyQuiet(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "example.com"},
		NotBefore: now.Add(-30 * 24 * time.Hour),
		NotAfter:  now.Add(180 * 24 * time.Hour),
	}
	fs := TLSAudit{}.expiryFindings("https://x", leaf)
	if len(fs) != 0 {
		t.Fatalf("want 0 findings for cert valid >30d, got %+v", fs)
	}
}

func TestTLSAuditHostnameUnitMatch(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}
	if _, ok := (TLSAudit{}).hostnameFinding("https://x", "example.com", leaf); ok {
		t.Fatal("want no finding when hostname matches")
	}
}

func TestTLSAuditHostnameUnitMismatch(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "other.example.com"},
		DNSNames: []string{"other.example.com"},
	}
	f, ok := (TLSAudit{}).hostnameFinding("https://x", "example.com", leaf)
	if !ok {
		t.Fatal("want a finding when hostname mismatches")
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Detail, "other.example.com") {
		t.Errorf("detail should list the cert's covered names; got %q", f.Detail)
	}
}

func TestTLSAuditHostnameMismatchEndToEnd(t *testing.T) {
	// Cert valid only for "not-the-host.example", served on 127.0.0.1.
	// The audit dials 127.0.0.1, asks for ServerName "127.0.0.1", and the
	// cert's VerifyHostname must reject it.
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(time.Hour)
	cert := generateTestCert(t, "not-the-host.example",
		[]string{"not-the-host.example"}, nil,
		notBefore, notAfter)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()
	go acceptOne(ln)

	u := &url.URL{Scheme: "https", Host: ln.Addr().String()}
	findings, err := TLSAudit{}.Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !containsTitle(findings, "TLS certificate hostname mismatch") {
		t.Fatalf("expected hostname-mismatch finding, got %+v", findings)
	}
}

func withFrozenNow(t *testing.T, now time.Time) {
	t.Helper()
	prev := tlsAuditNow
	tlsAuditNow = func() time.Time { return now }
	t.Cleanup(func() { tlsAuditNow = prev })
}

func containsTitle(fs []Finding, title string) bool {
	for _, f := range fs {
		if f.Title == title {
			return true
		}
	}
	return false
}

// generateTestCert builds a short-lived self-signed cert suitable for tls.Listen.
// We don't reuse httptest's cert because we need control over DNSNames/IPAddresses
// to provoke a hostname mismatch.
func generateTestCert(t *testing.T, cn string, dns []string, ips []net.IP, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("gen serial: %v", err)
	}
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        parsed,
	}
}

// acceptOne accepts a single connection, performs the TLS handshake, and
// closes it. Enough for the audit to inspect ConnectionState.
func acceptOne(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	if tc, ok := conn.(*tls.Conn); ok {
		_ = tc.Handshake()
	}
	_ = conn.Close()
}

func TestTLSAuditCipherStrongQuiet(t *testing.T) {
	// TLS 1.3 AEAD suites are all considered secure; no finding.
	fs := TLSAudit{}.cipherFinding("https://x", tls.TLS_AES_128_GCM_SHA256)
	if len(fs) != 0 {
		t.Fatalf("want 0 findings for strong AEAD cipher, got %+v", fs)
	}
}

func TestTLSAuditCipherWeakCBC(t *testing.T) {
	// CBC-only suite: no AEAD, padding-oracle prone, but not RC4/3DES.
	// Severity Medium.
	fs := TLSAudit{}.cipherFinding("https://x", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for CBC cipher, got %+v", fs)
	}
	if fs[0].Severity != SeverityMedium {
		t.Errorf("severity = %q, want medium", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Title, "CBC") {
		t.Errorf("title should name the cipher; got %q", fs[0].Title)
	}
}

func TestTLSAuditCipherWeakRC4High(t *testing.T) {
	fs := TLSAudit{}.cipherFinding("https://x", tls.TLS_RSA_WITH_RC4_128_SHA)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for RC4 cipher, got %+v", fs)
	}
	if fs[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (RC4 is broken)", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Title, "RC4") {
		t.Errorf("title should name the cipher; got %q", fs[0].Title)
	}
}

func TestTLSAuditCipherWeak3DESHigh(t *testing.T) {
	fs := TLSAudit{}.cipherFinding("https://x", tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding for 3DES cipher, got %+v", fs)
	}
	if fs[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want high (3DES is broken)", fs[0].Severity)
	}
}

func TestTLSAuditOCSPStaplePresentQuiet(t *testing.T) {
	fs := TLSAudit{}.ocspStapleFinding("https://x", []byte{0x30, 0x82, 0x00, 0x00})
	if len(fs) != 0 {
		t.Fatalf("want 0 findings when OCSP is stapled, got %+v", fs)
	}
}

func TestTLSAuditOCSPStapleAbsent(t *testing.T) {
	fs := TLSAudit{}.ocspStapleFinding("https://x", nil)
	if len(fs) != 1 || fs[0].Severity != SeverityLow {
		t.Fatalf("want 1 low finding for missing OCSP staple, got %+v", fs)
	}
	if fs[0].DedupeKey == "" {
		t.Errorf("DedupeKey empty")
	}
}

func TestTLSAuditSCTPresentFromHandshakeQuiet(t *testing.T) {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	fs := TLSAudit{}.sctFinding("https://x", leaf, [][]byte{{0x01, 0x02}})
	if len(fs) != 0 {
		t.Fatalf("want 0 findings when handshake delivers SCTs, got %+v", fs)
	}
}

func TestTLSAuditSCTEmptyHandshakeBytesStillFires(t *testing.T) {
	// A non-nil-but-empty entry should not satisfy CT compliance.
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	fs := TLSAudit{}.sctFinding("https://x", leaf, [][]byte{nil, {}})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding when SCT entries are empty, got %+v", fs)
	}
}

func TestTLSAuditSCTPresentEmbeddedQuiet(t *testing.T) {
	leaf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "example.com"},
		Extensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
			Value: []byte{0x04, 0x02, 0x00, 0x00},
		}},
	}
	fs := TLSAudit{}.sctFinding("https://x", leaf, nil)
	if len(fs) != 0 {
		t.Fatalf("want 0 findings when cert embeds an SCT extension, got %+v", fs)
	}
}

func TestTLSAuditSCTAbsent(t *testing.T) {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	fs := TLSAudit{}.sctFinding("https://x", leaf, nil)
	if len(fs) != 1 || fs[0].Severity != SeverityLow {
		t.Fatalf("want 1 low finding when SCTs are absent, got %+v", fs)
	}
}

func TestTLSAuditIntermediateExpiryExpired(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	intermediates := []*x509.Certificate{{
		Subject:   pkix.Name{CommonName: "Example Intermediate CA"},
		NotBefore: now.Add(-365 * 24 * time.Hour),
		NotAfter:  now.Add(-24 * time.Hour),
	}}
	fs := TLSAudit{}.intermediateExpiryFindings("https://x", intermediates)
	if len(fs) != 1 || fs[0].Severity != SeverityHigh {
		t.Fatalf("want 1 high finding for expired intermediate, got %+v", fs)
	}
	if !strings.Contains(fs[0].Title, "intermediate #1") {
		t.Errorf("title should identify chain position; got %q", fs[0].Title)
	}
}

func TestTLSAuditIntermediateExpiryNotYetValid(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	intermediates := []*x509.Certificate{{
		Subject:   pkix.Name{CommonName: "Example Intermediate CA"},
		NotBefore: now.Add(24 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
	}}
	fs := TLSAudit{}.intermediateExpiryFindings("https://x", intermediates)
	if len(fs) != 1 || fs[0].Severity != SeverityHigh {
		t.Fatalf("want 1 high finding for not-yet-valid intermediate, got %+v", fs)
	}
	if !strings.Contains(fs[0].Title, "not yet valid") {
		t.Errorf("title should mention not-yet-valid; got %q", fs[0].Title)
	}
}

func TestTLSAuditIntermediateExpirySoonWindow(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	intermediates := []*x509.Certificate{
		{
			Subject:   pkix.Name{CommonName: "Healthy Intermediate"},
			NotBefore: now.Add(-30 * 24 * time.Hour),
			NotAfter:  now.Add(180 * 24 * time.Hour),
		},
		{
			Subject:   pkix.Name{CommonName: "Soon-To-Expire Intermediate"},
			NotBefore: now.Add(-30 * 24 * time.Hour),
			NotAfter:  now.Add(20 * 24 * time.Hour),
		},
	}
	fs := TLSAudit{}.intermediateExpiryFindings("https://x", intermediates)
	if len(fs) != 1 {
		t.Fatalf("want 1 finding (only the expiring-soon one), got %+v", fs)
	}
	if fs[0].Severity != SeverityLow {
		t.Errorf("severity = %q, want low", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Title, "intermediate #2") {
		t.Errorf("title should identify the second intermediate; got %q", fs[0].Title)
	}
}

func TestTLSAuditIntermediateExpiryHealthyQuiet(t *testing.T) {
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	withFrozenNow(t, now)
	intermediates := []*x509.Certificate{{
		Subject:   pkix.Name{CommonName: "Healthy Intermediate"},
		NotBefore: now.Add(-365 * 24 * time.Hour),
		NotAfter:  now.Add(365 * 24 * time.Hour),
	}}
	fs := TLSAudit{}.intermediateExpiryFindings("https://x", intermediates)
	if len(fs) != 0 {
		t.Fatalf("want 0 findings for healthy intermediate, got %+v", fs)
	}
}

// TestTLSAuditWeakCipherEndToEnd stands up a listener that only offers a
// weak TLS 1.2 cipher (ECDHE-RSA-AES128-CBC-SHA) and confirms the audit
// emits the weak-cipher finding. Validates the wire-level path, not just
// the helper.
func TestTLSAuditWeakCipherEndToEnd(t *testing.T) {
	cert := generateTestCert(t, "127.0.0.1", nil, []net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		// Match the ECDSA test cert; the RSA CBC variant would fail to
		// negotiate against an ECDSA key.
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()
	go acceptOne(ln)

	u := &url.URL{Scheme: "https", Host: ln.Addr().String()}
	findings, err := TLSAudit{}.Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !containsTitleSubstring(findings, "weak TLS cipher suite negotiated") {
		t.Fatalf("expected weak-cipher finding, got %+v", findings)
	}
}

// TestTLSAuditNoStapleNoSCTEndToEnd stands up a vanilla TLS listener with
// no OCSP staple and no embedded SCTs, then confirms both hardening
// findings fire through the real handshake path.
func TestTLSAuditNoStapleNoSCTEndToEnd(t *testing.T) {
	cert := generateTestCert(t, "127.0.0.1", nil, []net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()
	go acceptOne(ln)

	u := &url.URL{Scheme: "https", Host: ln.Addr().String()}
	findings, err := TLSAudit{}.Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !containsTitle(findings, "TLS handshake did not include a stapled OCSP response") {
		t.Errorf("expected missing-OCSP-staple finding, got %+v", findings)
	}
	if !containsTitle(findings, "TLS leaf certificate carries no Signed Certificate Timestamps") {
		t.Errorf("expected missing-SCT finding, got %+v", findings)
	}
}

func containsTitleSubstring(fs []Finding, substr string) bool {
	for _, f := range fs {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}
