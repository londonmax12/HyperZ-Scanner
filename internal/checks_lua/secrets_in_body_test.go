package checks_lua

import (
	"context"
	"net/http"
	"testing"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/page"
)

func findSecrets(t *testing.T) checks.Check {
	t.Helper()
	for _, c := range All() {
		if c.Name() == "secrets-in-body" {
			return c
		}
	}
	t.Fatal("secrets-in-body Lua check not found")
	return nil
}

// secretsPage builds an in-memory Page so tests skip the network and
// stay deterministic across runs. The content-type controls the
// scannable-CT short-circuit; pass "" to exercise the absent-CT path
// (which the Go check treats as scannable).
func secretsPage(body, ct string) page.Page {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return page.Page{
		URL:     "https://example.com/page",
		Status:  200,
		Headers: h,
		Body:    []byte(body),
		Fetched: true,
	}
}

// TestLuaSecretsParity sweeps a representative cross-section of
// secret shapes. The Go check is the parity oracle for dedupe keys
// and severity; finding count and DedupeKey + Severity drift across
// the implementations should fail here.
func TestLuaSecretsParity(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "clean", body: "just plain text, nothing interesting"},
		{name: "aws_key", body: `AKIAIOSFODNN7EXAMPLE somewhere in the body`},
		{name: "pem_private_key", body: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJ...\n-----END RSA PRIVATE KEY-----"},
		{name: "jwt", body: "Authorization: Bearer eyJabcdefgh.eyJabcdefgh.abcdefgh"},
		{name: "github_pat", body: "tokens like ghp_abcdefghijklmnopqrstuvwxyzABCD1234 leak"},
		{name: "two_distinct", body: "AKIAIOSFODNN7EXAMPLE and AKIAJBCDEFGHIJ12345Z"},
	}

	lua := findSecrets(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := secretsPage(tc.body, "text/html")
			goFs, err := (checks.SecretsInBody{}).Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("go: %v", err)
			}
			luaFs, err := lua.Run(context.Background(), nil, nil, p)
			if err != nil {
				t.Fatalf("lua: %v", err)
			}
			if len(goFs) != len(luaFs) {
				t.Fatalf("count: go=%d lua=%d (go=%+v lua=%+v)", len(goFs), len(luaFs), goFs, luaFs)
			}
			for i := range goFs {
				if goFs[i].DedupeKey != luaFs[i].DedupeKey {
					t.Errorf("[%d] dedupe drift: go=%q lua=%q", i, goFs[i].DedupeKey, luaFs[i].DedupeKey)
				}
				if goFs[i].Severity != luaFs[i].Severity {
					t.Errorf("[%d] severity drift: go=%q lua=%q", i, goFs[i].Severity, luaFs[i].Severity)
				}
				if goFs[i].Title != luaFs[i].Title {
					t.Errorf("[%d] title drift: go=%q lua=%q", i, goFs[i].Title, luaFs[i].Title)
				}
				if len(goFs[i].Details) != len(luaFs[i].Details) {
					t.Errorf("[%d] details count: go=%d lua=%d", i, len(goFs[i].Details), len(luaFs[i].Details))
				}
			}
		})
	}
}

func TestLuaSecretsBinaryCTSkipped(t *testing.T) {
	// image/png is non-scannable -> no findings even if the bytes
	// happen to match a secret pattern.
	p := secretsPage("AKIAIOSFODNN7EXAMPLE", "image/png")
	fs, err := findSecrets(t).Run(context.Background(), nil, nil, p)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("binary CT should produce no findings, got %d", len(fs))
	}
}
