package checks

import (
	"strings"
	"testing"
)

func TestSnippetCentersOnByteExactNeedle(t *testing.T) {
	body := []byte(strings.Repeat("x", 500) + "<svg onload=alert('hpzc0001')>" + strings.Repeat("y", 500))
	needle := []byte("<svg onload=alert('hpzc0001')>")
	got := snippet(body, needle, false)
	if !strings.Contains(got, string(needle)) {
		t.Errorf("snippet missing needle: %q", got)
	}
	// window=120 on each side + the needle itself - allow a small slack
	// for the TrimSpace step (a no-op here, but be permissive).
	if maxLen := len(needle) + 2*snippetWindow + 8; len(got) > maxLen {
		t.Errorf("snippet too long: %d bytes, max %d", len(got), maxLen)
	}
	if len(got) < len(needle) {
		t.Errorf("snippet shorter than needle: %d < %d", len(got), len(needle))
	}
}

func TestSnippetCaseInsensitiveFindsAndPreservesOriginalCasing(t *testing.T) {
	// SQL pattern lookup runs on lowercased pattern + lowercased body;
	// we want the snippet to preserve the ORIGINAL casing the server sent.
	body := []byte(strings.Repeat("x", 200) + "You Have An Error In Your SQL Syntax" + strings.Repeat("y", 200))
	got := snippet(body, []byte("you have an error in your sql syntax"), true)
	if !strings.Contains(got, "You Have An Error In Your SQL Syntax") {
		t.Errorf("snippet should preserve original casing: %q", got)
	}
	if strings.Contains(got, "you have an error in your sql syntax") {
		t.Errorf("snippet returned lowercased text; original casing was lost: %q", got)
	}
}

func TestSnippetMissingNeedleReturnsNeedle(t *testing.T) {
	got := snippet([]byte("no match here"), []byte("needle"), false)
	if got != "needle" {
		t.Errorf("got %q, want %q (fallback to bare needle)", got, "needle")
	}
	gotCI := snippet([]byte("no match here"), []byte("needle"), true)
	if gotCI != "needle" {
		t.Errorf("got %q, want %q (case-insensitive fallback to bare needle)", gotCI, "needle")
	}
}

func TestSnippetEmptyNeedleReturnsEmpty(t *testing.T) {
	if got := snippet([]byte("body"), nil, false); got != "" {
		t.Errorf("empty needle should return empty string, got %q", got)
	}
}

func TestSnippetClampsAtBodyBoundaries(t *testing.T) {
	// Needle at byte 0 - left-side window must clamp to 0, no panic.
	body := []byte("<svg>" + strings.Repeat("x", 50))
	got := snippet(body, []byte("<svg>"), false)
	if !strings.HasPrefix(got, "<svg>") {
		t.Errorf("snippet at body start should begin with needle: %q", got)
	}
	// Needle near body end - right-side window must clamp to len(body).
	body2 := []byte(strings.Repeat("x", 50) + "<svg>")
	got2 := snippet(body2, []byte("<svg>"), false)
	if !strings.HasSuffix(got2, "<svg>") {
		t.Errorf("snippet at body end should finish with needle: %q", got2)
	}
}
