package proxy

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestParseProxyAcceptsKnownSchemes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1.1.1.1:8080", "http://1.1.1.1:8080"},
		{"http://h:1", "http://h:1"},
		{"https://h:1", "https://h:1"},
		{"socks5://h:1", "socks5://h:1"},
		{"socks5h://h:1", "socks5h://h:1"},
	}
	for _, c := range cases {
		u, err := parseProxy(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if u.String() != c.want {
			t.Fatalf("%q → %q, want %q", c.in, u.String(), c.want)
		}
	}
}

func TestParseProxyRejectsBadInput(t *testing.T) {
	cases := []string{
		"ftp://h:1",         // unsupported scheme
		"http://",           // missing host
		"socks4://h:1",      // unsupported scheme
	}
	for _, in := range cases {
		if _, err := parseProxy(in); err == nil {
			t.Fatalf("%q: expected error, got nil", in)
		}
	}
}

func TestLoadDedupesAndDefaultsScheme(t *testing.T) {
	urls, err := Load([]string{
		"http://1.1.1.1:8080",
		"socks5://2.2.2.2:1080",
		"3.3.3.3:3128",
		"1.1.1.1:8080", // duplicate after inferring scheme
		"http://1.1.1.1:8080", // exact duplicate
	}, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(urls) != 3 {
		t.Fatalf("got %d urls, want 3: %v", len(urls), urls)
	}
}

func TestLoadIgnoresBlanksAndComments(t *testing.T) {
	urls, err := Load([]string{
		"   ",
		"# header comment",
		"http://1.1.1.1:8080",
	}, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(urls) != 1 || urls[0].String() != "http://1.1.1.1:8080" {
		t.Fatalf("urls = %v, want [http://1.1.1.1:8080]", urls)
	}
}

func TestLoadReturnsErrorOnBadInline(t *testing.T) {
	_, err := Load([]string{"ftp://nope:1"}, "")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxies.txt")
	body := "# comment\n\nhttp://1.1.1.1:8080\n2.2.2.2:3128\n  # indented comment\nhttp://1.1.1.1:8080\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	urls, err := Load(nil, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := make([]string, 0, len(urls))
	for _, u := range urls {
		got = append(got, u.String())
	}
	sort.Strings(got)
	want := []string{"http://1.1.1.1:8080", "http://2.2.2.2:3128"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load(nil, filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadMergesInlineAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.txt")
	if err := os.WriteFile(path, []byte("http://shared:1\nhttp://only-file:1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	urls, err := Load([]string{"http://shared:1", "http://only-inline:1"}, path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := make([]string, 0, len(urls))
	for _, u := range urls {
		got = append(got, u.String())
	}
	sort.Strings(got)
	want := []string{"http://only-file:1", "http://only-inline:1", "http://shared:1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractHostPorts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"plain list", "1.1.1.1:8080\n2.2.2.2:3128", []string{"1.1.1.1:8080", "2.2.2.2:3128"}},
		{"junk wrapper", "<li>4.4.4.4:1080 (us)</li>", []string{"4.4.4.4:1080"}},
		{"hostname", "proxy.example.com:80", []string{"proxy.example.com:80"}},
		{"no host:port", "no proxies here", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractHostPorts(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}
