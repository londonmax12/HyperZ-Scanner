package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/londonball/hyperz/internal/page"
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
	// 127.0.0.1/::1/example.com and negotiates TLS 1.2+. No findings.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	findings, err := TLSAudit{}.Run(context.Background(), nil, nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on modern HTTPS, got %d: %+v", len(findings), findings)
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
			fs := TLSAudit{}.versionFinding("https://x", "https://x", tt.version)
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
	fs := TLSAudit{}.expiryFindings("https://x", "https://x", leaf)
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
	fs := TLSAudit{}.expiryFindings("https://x", "https://x", leaf)
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
	fs := TLSAudit{}.expiryFindings("https://x", "https://x", leaf)
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
	fs := TLSAudit{}.expiryFindings("https://x", "https://x", leaf)
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
	fs := TLSAudit{}.expiryFindings("https://x", "https://x", leaf)
	if len(fs) != 0 {
		t.Fatalf("want 0 findings for cert valid >30d, got %+v", fs)
	}
}

func TestTLSAuditHostnameUnitMatch(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}
	if _, ok := (TLSAudit{}).hostnameFinding("https://x", "https://x", "example.com", leaf); ok {
		t.Fatal("want no finding when hostname matches")
	}
}

func TestTLSAuditHostnameUnitMismatch(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "other.example.com"},
		DNSNames: []string{"other.example.com"},
	}
	f, ok := (TLSAudit{}).hostnameFinding("https://x", "https://x", "example.com", leaf)
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
