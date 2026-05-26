package checks_lua

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
	"sort"
	"testing"
	"time"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findTLSAudit(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "tls-audit" {
			return c
		}
	}
	t.Fatal("tls-audit Lua check not found")
	return nil
}

// TestLuaTLSAuditSkipsHTTPParity asserts both implementations stay
// quiet for http:// targets (no TLS to inspect, no findings to emit).
func TestLuaTLSAuditSkipsHTTPParity(t *testing.T) {
	goFs, err := (checks.TLSAudit{}).Run(context.Background(), nil, nil, page.FromURL("http://example.com/"))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findTLSAudit(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, page.FromURL("http://example.com/"))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	if len(goFs) != 0 || len(luaFs) != 0 {
		t.Errorf("http:// must produce 0 findings on both: go=%d lua=%d", len(goFs), len(luaFs))
	}
}

// TestLuaTLSAuditHappyPathParity locks in that both implementations
// emit the same set of findings against httptest.NewTLSServer (which
// negotiates TLS 1.3 with a strong cipher; expects the two Low
// hardening findings, no Medium+).
func TestLuaTLSAuditHappyPathParity(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	goFs, err := (checks.TLSAudit{}).Run(context.Background(), nil, nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findTLSAudit(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, page.FromURL(srv.URL))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}
	assertFindingSetParity(t, goFs, luaFs)
}

// TestLuaTLSAuditExpiredCertParity locks in the leaf-expired finding:
// with the clock frozen forward past the cert's NotAfter, both impls
// must fire one High "TLS certificate has expired" finding with
// identical DedupeKey.
func TestLuaTLSAuditExpiredCertParity(t *testing.T) {
	// Cert valid only until 30 days ago relative to the frozen clock.
	frozen := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	cert := generateLuaTestCert(t, "127.0.0.1",
		nil, []net.IP{net.ParseIP("127.0.0.1")},
		frozen.Add(-365*24*time.Hour),
		frozen.Add(-24*time.Hour))
	addr := startLuaTestTLSListener(t, cert, nil)

	restore := checks.SetTLSAuditNowForTest(frozen)
	defer restore()

	u := &url.URL{Scheme: "https", Host: addr}
	goFs, err := (checks.TLSAudit{}).Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findTLSAudit(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "TLS certificate has expired")
	luaHit := pickByTitleSubstr(luaFs, "TLS certificate has expired")
	if goHit == nil || luaHit == nil {
		t.Fatalf("expired-cert must fire on both: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
}

// TestLuaTLSAuditExpiringSoonParity locks in the within-30-days band:
// both impls must emit one Low "expires in X days" finding with
// matching DedupeKey.
func TestLuaTLSAuditExpiringSoonParity(t *testing.T) {
	frozen := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	cert := generateLuaTestCert(t, "127.0.0.1",
		nil, []net.IP{net.ParseIP("127.0.0.1")},
		frozen.Add(-30*24*time.Hour),
		frozen.Add(20*24*time.Hour))
	addr := startLuaTestTLSListener(t, cert, nil)

	restore := checks.SetTLSAuditNowForTest(frozen)
	defer restore()

	u := &url.URL{Scheme: "https", Host: addr}
	goFs, err := (checks.TLSAudit{}).Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findTLSAudit(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "expires in")
	luaHit := pickByTitleSubstr(luaFs, "expires in")
	if goHit == nil || luaHit == nil {
		t.Fatalf("expires-in must fire on both: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != checks.SeverityLow || luaHit.Severity != checks.SeverityLow {
		t.Errorf("severity drift: go=%q lua=%q (want both low)", goHit.Severity, luaHit.Severity)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
}

// TestLuaTLSAuditHostnameMismatchParity locks in the hostname-mismatch
// arm: a cert valid for one DNS name served on a different address
// must fire one High finding on both impls. Uses real TLS dial.
func TestLuaTLSAuditHostnameMismatchParity(t *testing.T) {
	cert := generateLuaTestCert(t, "not-the-host.example",
		[]string{"not-the-host.example"}, nil,
		time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	addr := startLuaTestTLSListener(t, cert, nil)

	u := &url.URL{Scheme: "https", Host: addr}
	goFs, err := (checks.TLSAudit{}).Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findTLSAudit(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "hostname mismatch")
	luaHit := pickByTitleSubstr(luaFs, "hostname mismatch")
	if goHit == nil || luaHit == nil {
		t.Fatalf("hostname-mismatch must fire on both: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
}

// TestLuaTLSAuditWeakCipherParity locks in the weak-cipher arm:
// against a server that only offers an ECDHE-CBC-SHA cipher, both
// impls must emit a Medium "weak TLS cipher suite negotiated" finding
// with matching DedupeKey.
func TestLuaTLSAuditWeakCipherParity(t *testing.T) {
	cert := generateLuaTestCert(t, "127.0.0.1", nil, []net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	addr := startLuaTestTLSListener(t, cert, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
	})

	u := &url.URL{Scheme: "https", Host: addr}
	goFs, err := (checks.TLSAudit{}).Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("go: %v", err)
	}
	luaC := findTLSAudit(t)
	luaFs, err := luaC.Run(context.Background(), nil, nil, page.FromURL(u.String()))
	if err != nil {
		t.Fatalf("lua: %v", err)
	}

	goHit := pickByTitleSubstr(goFs, "weak TLS cipher suite negotiated")
	luaHit := pickByTitleSubstr(luaFs, "weak TLS cipher suite negotiated")
	if goHit == nil || luaHit == nil {
		t.Fatalf("weak-cipher must fire on both: go=%+v lua=%+v", goFs, luaFs)
	}
	if goHit.Severity != luaHit.Severity {
		t.Errorf("severity drift: go=%q lua=%q", goHit.Severity, luaHit.Severity)
	}
	if goHit.DedupeKey != luaHit.DedupeKey {
		t.Errorf("dedupe drift: go=%q lua=%q", goHit.DedupeKey, luaHit.DedupeKey)
	}
}

// assertFindingSetParity asserts go and lua produce the same set of
// (Severity, Title, DedupeKey) triples. Order-insensitive because the
// two impls walk per-finding helpers in the same order today, but the
// contract is on the set, not the sequence.
func assertFindingSetParity(t *testing.T, goFs, luaFs []checks.Finding) {
	t.Helper()
	if len(goFs) != len(luaFs) {
		t.Fatalf("finding count drift: go=%d lua=%d\ngo=%+v\nlua=%+v",
			len(goFs), len(luaFs), goFs, luaFs)
	}
	keyOf := func(f checks.Finding) string {
		return string(f.Severity) + "|" + f.Title + "|" + f.DedupeKey
	}
	goKeys := make([]string, len(goFs))
	luaKeys := make([]string, len(luaFs))
	for i := range goFs {
		goKeys[i] = keyOf(goFs[i])
	}
	for i := range luaFs {
		luaKeys[i] = keyOf(luaFs[i])
	}
	sort.Strings(goKeys)
	sort.Strings(luaKeys)
	for i := range goKeys {
		if goKeys[i] != luaKeys[i] {
			t.Errorf("finding[%d] drift:\n go=%s\nlua=%s", i, goKeys[i], luaKeys[i])
		}
	}
}

// generateLuaTestCert builds a short-lived ECDSA self-signed cert
// suitable for tls.Listen. Mirrors the helper in
// internal/checks/tls_audit_test.go - duplicated here so the
// checks_lua tests do not depend on the internal/checks test binary.
func generateLuaTestCert(t *testing.T, cn string, dns []string, ips []net.IP, notBefore, notAfter time.Time) tls.Certificate {
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

// startLuaTestTLSListener spins up a tls.Listener on 127.0.0.1:0
// returning the bound address. If cfg is nil the listener serves cert
// with default TLS settings; pass a cfg to constrain version / cipher
// (used by the weak-cipher test). Accepts one connection and closes;
// the audit only needs to inspect ConnectionState.
func startLuaTestTLSListener(t *testing.T, cert tls.Certificate, cfg *tls.Config) string {
	t.Helper()
	if cfg == nil {
		cfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}
