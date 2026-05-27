package target

import "testing"

func TestCanonicalKeyDedupesIdenticalPages(t *testing.T) {
	a := Page("https://example.com/foo", "crawler")
	b := Page("https://example.com/foo", "check:openapi-audit")
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatalf("expected same canonical key regardless of origin: %q vs %q",
			a.CanonicalKey(), b.CanonicalKey())
	}
}

func TestCanonicalKeyStripsFragment(t *testing.T) {
	a := Page("https://example.com/foo", "crawler")
	b := Page("https://example.com/foo#section", "crawler")
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatalf("fragment must not affect canonical key: %q vs %q",
			a.CanonicalKey(), b.CanonicalKey())
	}
}

func TestCanonicalKeyLowercasesHost(t *testing.T) {
	a := Page("https://Example.COM/foo", "crawler")
	b := Page("https://example.com/foo", "crawler")
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatalf("host case must not affect canonical key: %q vs %q",
			a.CanonicalKey(), b.CanonicalKey())
	}
}

func TestCanonicalKeyDistinguishesKinds(t *testing.T) {
	p := Page("https://example.com/api/login", "crawler")
	e := Endpoint("https://example.com/api/login", "POST", "application/json", "crawler")
	if p.CanonicalKey() == e.CanonicalKey() {
		t.Fatalf("KindPage and KindEndpoint at the same URL must not collide: %q",
			p.CanonicalKey())
	}
}

func TestCanonicalKeyDistinguishesEndpointMethod(t *testing.T) {
	get := Endpoint("https://example.com/api/login", "GET", "application/json", "crawler")
	post := Endpoint("https://example.com/api/login", "POST", "application/json", "crawler")
	if get.CanonicalKey() == post.CanonicalKey() {
		t.Fatalf("endpoint method must differentiate: %q == %q",
			get.CanonicalKey(), post.CanonicalKey())
	}
}

func TestCanonicalKeyEndpointFoldsContentTypeFamily(t *testing.T) {
	a := Endpoint("https://example.com/api/x", "POST", "application/json; charset=utf-8", "crawler")
	b := Endpoint("https://example.com/api/x", "POST", "application/json", "crawler")
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatalf("content-type parameters must not differentiate: %q vs %q",
			a.CanonicalKey(), b.CanonicalKey())
	}
}

func TestCanonicalKeyParamDistinguishesNameAndLocation(t *testing.T) {
	q := Param("https://example.com/search", "q", "query", "crawler")
	body := Param("https://example.com/search", "q", "body", "crawler")
	other := Param("https://example.com/search", "page", "query", "crawler")
	if q.CanonicalKey() == body.CanonicalKey() {
		t.Fatalf("param location must differentiate")
	}
	if q.CanonicalKey() == other.CanonicalKey() {
		t.Fatalf("param name must differentiate")
	}
}

func TestCanonicalKeyNoteDoesNotAffect(t *testing.T) {
	a := Page("https://example.com/", "crawler")
	b := Page("https://example.com/", "crawler")
	b.Note = "stored-xss-readback:tok123"
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatalf("Note must not affect canonical key (opaque to dispatcher)")
	}
}

func TestCanonicalKeyMalformedURLFallsBackToRaw(t *testing.T) {
	a := Page("::::not-a-url", "crawler")
	b := Page("::::not-a-url", "crawler")
	c := Page("::::other-bad", "crawler")
	if a.CanonicalKey() != b.CanonicalKey() {
		t.Fatalf("identical malformed inputs must produce identical keys")
	}
	if a.CanonicalKey() == c.CanonicalKey() {
		t.Fatalf("distinct malformed inputs must NOT collapse to one key")
	}
}

func TestHostReturnsLowercaseSchemeHost(t *testing.T) {
	got := Page("https://Example.COM:8443/foo?bar=baz", "crawler").Host()
	want := "https://example.com:8443"
	if got != want {
		t.Fatalf("Host() = %q, want %q", got, want)
	}
}

func TestHostEmptyForMalformedURL(t *testing.T) {
	if got := Page("::::bad", "crawler").Host(); got != "" {
		t.Fatalf("Host() for malformed URL = %q, want \"\"", got)
	}
}
