package checks

import (
	"strings"
	"testing"
)

func TestNewCanaryShape(t *testing.T) {
	c := NewCanary()
	if !strings.HasPrefix(c, canaryPrefix) {
		t.Errorf("canary %q missing prefix %q", c, canaryPrefix)
	}
	if got, want := len(c), len(canaryPrefix)+canaryHexLen; got != want {
		t.Errorf("canary %q length = %d, want %d", c, got, want)
	}
	if !IsCanary(c) {
		t.Errorf("IsCanary(%q) = false, want true", c)
	}
}

func TestNewCanaryUnique(t *testing.T) {
	// 1000 tokens with 48 random bits have a vanishing collision probability
	// (birthday bound ~2^-28). Any duplicate here means the generator is
	// not actually using crypto/rand.
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		c := NewCanary()
		if _, dup := seen[c]; dup {
			t.Fatalf("duplicate canary %q at iteration %d", c, i)
		}
		seen[c] = struct{}{}
	}
}

func TestIsCanary(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"hpzc0123456789ab", true},
		{"hpzcabcdef012345", true},
		{"hpzc", false},                // prefix only
		{"hpzcZZZZZZZZZZZZ", false},    // non-hex
		{"hpzc0123456789abZ", false},   // too long
		{"hpzc0123456789a", false},     // too short
		{"HPZC0123456789ab", false},    // case-sensitive prefix
		{"hpz0123456789ab", false},     // wrong prefix
		{"", false},
		{"hello world", false},
	}
	for _, tc := range cases {
		if got := IsCanary(tc.s); got != tc.want {
			t.Errorf("IsCanary(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}
