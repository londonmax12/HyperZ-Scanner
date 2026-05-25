package oob

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBuiltinRegisterCanaryShape(t *testing.T) {
	b := NewBuiltin(":0", "scanner.example.com:9999")
	c := b.Register("ssrf", map[string]string{"sink": "url"})
	if c.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if !strings.HasPrefix(c.HTTPURL, "http://scanner.example.com:9999/") {
		t.Errorf("HTTPURL %q does not embed callback host", c.HTTPURL)
	}
	if !strings.HasSuffix(c.HTTPURL, c.Token) {
		t.Errorf("HTTPURL %q does not end with token %q", c.HTTPURL, c.Token)
	}
}

func TestBuiltinRegistrationsIndex(t *testing.T) {
	b := NewBuiltin(":0", "h")
	c1 := b.Register("ssrf", map[string]string{"sink": "url"})
	c2 := b.Register("ssrf", map[string]string{"sink": "callback"})
	_ = b.Register("xxe", nil)

	got := b.Registrations("ssrf")
	if len(got) != 2 {
		t.Fatalf("want 2 ssrf registrations, got %d", len(got))
	}
	if got[0].Canary.Token != c1.Token || got[1].Canary.Token != c2.Token {
		t.Errorf("registration order not preserved")
	}
	if got[0].Extra["sink"] != "url" || got[1].Extra["sink"] != "callback" {
		t.Errorf("extra metadata not stored verbatim")
	}
	if len(b.Registrations("xxe")) != 1 {
		t.Errorf("xxe registration count wrong")
	}
	if len(b.Registrations("ssti")) != 0 {
		t.Errorf("unregistered check should return empty slice")
	}
}

func TestBuiltinExtraIsolatedFromCaller(t *testing.T) {
	b := NewBuiltin(":0", "h")
	extra := map[string]string{"sink": "url"}
	b.Register("ssrf", extra)
	extra["sink"] = "mutated"
	got := b.Registrations("ssrf")
	if got[0].Extra["sink"] != "url" {
		t.Errorf("server stored caller's mutable map; want isolation")
	}
}

func TestBuiltinHitRoundTrip(t *testing.T) {
	b := NewBuiltin("127.0.0.1:0", "")
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Stop(context.Background())

	canary := b.Register("ssrf", map[string]string{"sink": "url"})
	hitURL := "http://" + b.LocalAddr() + "/" + canary.Token

	resp, err := http.Get(hitURL)
	if err != nil {
		t.Fatalf("GET canary: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	hits := b.Hits(canary.Token)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if hits[0].Token != canary.Token {
		t.Errorf("hit token mismatch: %q vs %q", hits[0].Token, canary.Token)
	}
	if hits[0].Protocol != "http" {
		t.Errorf("hit protocol = %q, want http", hits[0].Protocol)
	}
	if hits[0].Method != http.MethodGet {
		t.Errorf("hit method = %q, want GET", hits[0].Method)
	}
}

func TestBuiltinHitUnknownToken(t *testing.T) {
	b := NewBuiltin("127.0.0.1:0", "")
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Stop(context.Background())

	// Issue a request whose path segment is NOT a registered token. The
	// hit should still be recorded so the operator can debug why a
	// target dropped the token segment, but Registrations for any
	// check should remain empty.
	resp, err := http.Get("http://" + b.LocalAddr() + "/no-such-token")
	if err != nil {
		t.Fatalf("GET unknown: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if len(b.Registrations("ssrf")) != 0 {
		t.Errorf("unknown-token hit should not appear under any check")
	}
	if hits := b.Hits("no-such-token"); len(hits) != 1 {
		t.Errorf("want unattributed hit recorded under token, got %d", len(hits))
	}
}

func TestBuiltinStartStopIdempotent(t *testing.T) {
	b := NewBuiltin("127.0.0.1:0", "h")
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Errorf("second stop should be no-op, got %v", err)
	}
	// Re-start after stop is rejected: a Server is one-shot per scan.
	if err := b.Start(context.Background()); err == nil {
		t.Errorf("restart after stop should fail")
	}
}

func TestBuiltinRegisterAssetServesBody(t *testing.T) {
	b := NewBuiltin("127.0.0.1:0", "")
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Stop(context.Background())

	body := `<!ENTITY % file SYSTEM "file:///etc/hostname">`
	canary := b.RegisterAsset("xxe", body, "application/xml-dtd", map[string]string{"variant": "oob-dtd-loader"})
	hitURL := "http://" + b.LocalAddr() + "/" + canary.Token

	resp, err := http.Get(hitURL)
	if err != nil {
		t.Fatalf("GET asset canary: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "application/xml-dtd" {
		t.Errorf("Content-Type = %q, want application/xml-dtd", ct)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}

	// Hit must still be recorded under the canary's token so Drain can
	// observe that the parser fetched the asset.
	hits := b.Hits(canary.Token)
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	// And the registration must still index under the named check.
	regs := b.Registrations("xxe")
	if len(regs) != 1 || regs[0].Extra["variant"] != "oob-dtd-loader" {
		t.Errorf("asset registration not indexed correctly: %+v", regs)
	}
}

func TestBuiltinRegisterAssetDefaultsContentType(t *testing.T) {
	b := NewBuiltin("127.0.0.1:0", "")
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Stop(context.Background())

	canary := b.RegisterAsset("xxe", "body-bytes", "", nil)
	resp, err := http.Get("http://" + b.LocalAddr() + "/" + canary.Token)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("empty content-type should default to application/octet-stream, got %q", ct)
	}
}

func TestBuiltinRegisterCoexistsWithAsset(t *testing.T) {
	b := NewBuiltin("127.0.0.1:0", "")
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer b.Stop(context.Background())

	plain := b.Register("xxe", nil)
	asset := b.RegisterAsset("xxe", "<!-- dtd -->", "application/xml-dtd", nil)

	// Plain canary still gets the default reply.
	resp, err := http.Get("http://" + b.LocalAddr() + "/" + plain.Token)
	if err != nil {
		t.Fatalf("GET plain: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "ok\n" {
		t.Errorf("plain canary body = %q, want \"ok\\n\"", got)
	}

	// Asset canary gets the asset body.
	resp2, err := http.Get("http://" + b.LocalAddr() + "/" + asset.Token)
	if err != nil {
		t.Fatalf("GET asset: %v", err)
	}
	got2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(got2) != "<!-- dtd -->" {
		t.Errorf("asset canary body = %q, want DTD content", got2)
	}
}

func TestExtractToken(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/abc", "abc"},
		{"/abc/extra/path", "abc"},
		{"abc", "abc"},
		{"//abc//", "abc"},
		{"/", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractToken(c.path); got != c.want {
			t.Errorf("extractToken(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
