package checks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/londonmax12/hyperz/internal/oob"
	"github.com/londonmax12/hyperz/internal/page"
)

// startOOB boots a Builtin listener on an ephemeral port and registers a
// teardown to stop it. Returns the running server so the test can mint
// canaries and inspect hits directly. The callback host stored on the
// listener is left empty; tests wrap with oobHostWrapper to rewrite
// canary HTTPURLs to point at the OS-assigned port.
func startOOB(t *testing.T) *oob.Builtin {
	t.Helper()
	srv := oob.NewBuiltin("127.0.0.1:0", "")
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("oob start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })
	return srv
}

func TestSSRFOOBDetection(t *testing.T) {
	oobSrv := startOOB(t)

	// vulnerable target: any ?url=X causes the server to http.Get(X).
	// That GET should land on the OOB listener if the canary URL was
	// embedded correctly.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("url")
		if got == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Issue the SSRF fetch synchronously so the listener hit is
		// recorded before this handler returns - keeps the test
		// deterministic without polling.
		resp, err := http.Get(got)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// Run SSRF with the OOB server attached. We need to patch the
	// canary URL the SSRF check mints to point at the listener's
	// actually-bound address; the simplest path is to rewrite the
	// server's host field via a wrapper.
	srv := newOOBHostWrapper(oobSrv)
	ctx := WithOOB(context.Background(), srv)

	// Use a sink the SSRF candidate generator will produce: query param
	// "url" is in the specific list, so it rides at every level.
	pg := page.FromURL(target.URL + "/api/proxy")
	_, err := SSRF{}.Run(ctx, newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The OOB fetch is synchronous through the target handler, so by
	// the time Run returns the hit is already in the listener index.
	findings := SSRF{}.Drain(ctx)
	if len(findings) == 0 {
		t.Fatalf("expected at least one OOB finding, got none. registrations=%d",
			len(srv.Registrations("ssrf")))
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(f.Title, "OOB-confirmed") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no OOB-confirmed finding in results: %+v", findings)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
	if got.CWE != "CWE-918" {
		t.Errorf("CWE = %q, want CWE-918", got.CWE)
	}
}

func TestXXEOOBDetection(t *testing.T) {
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	// Synthetic vulnerable XXE target: extracts the SYSTEM "URL" from
	// the posted XML and http.Gets it. A real XML parser would do the
	// same work via external entity resolution.
	systemRe := regexp.MustCompile(`SYSTEM "([^"]+)"`)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := systemRe.FindStringSubmatch(string(body))
		if len(m) == 2 {
			resp, err := http.Get(m[1])
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	ctx := WithOOB(context.Background(), srv)
	pg := page.Page{
		URL: target.URL + "/upload.xml",
		Headers: http.Header{
			"Content-Type": []string{"application/xml"},
		},
	}
	_, err := XXE{}.Run(ctx, newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := XXE{}.Drain(ctx)
	if len(findings) == 0 {
		t.Fatalf("expected at least one OOB finding, registrations=%d",
			len(srv.Registrations("xxe")))
	}
	got := findings[0]
	if got.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
	if !strings.Contains(got.Title, "OOB-confirmed") {
		t.Errorf("title should mark OOB confirmation: %q", got.Title)
	}
	if got.CWE != "CWE-611" {
		t.Errorf("CWE = %q, want CWE-611", got.CWE)
	}
}

func TestSSTIOOBDetection(t *testing.T) {
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	// Synthetic vulnerable SSTI target: detects an ERB-shaped payload
	// in the q parameter, extracts the canary URL, and http.Gets it.
	erbRe := regexp.MustCompile(`open\('([^']+)'\)`)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if m := erbRe.FindStringSubmatch(q); len(m) == 2 {
			resp, err := http.Get(m[1])
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	ctx := WithOOB(context.Background(), srv)
	pg := page.Page{
		URL: target.URL + "/?q=x",
	}
	_, err := SSTI{}.Run(ctx, newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := SSTI{}.Drain(ctx)
	if len(findings) == 0 {
		t.Fatalf("expected at least one OOB finding, registrations=%d",
			len(srv.Registrations("ssti")))
	}
	// The ERB payload is the only one this synthetic target evaluates,
	// so the registered engine should be erb.
	var erbFinding Finding
	for _, f := range findings {
		if strings.Contains(f.Title, "erb engine") {
			erbFinding = f
			break
		}
	}
	if erbFinding.Title == "" {
		t.Fatalf("no erb-engine finding in results: %+v", findings)
	}
	if erbFinding.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", erbFinding.Severity)
	}
}

func TestCmdInjectionBlindOOBDetection(t *testing.T) {
	oobSrv := startOOB(t)
	srv := newOOBHostWrapper(oobSrv)

	// Synthetic vulnerable target: extracts a "curl <URL>" sequence
	// from the host query parameter and http.Gets it. Mirrors a real
	// backend that splices ?host=... into a shell command.
	curlRe := regexp.MustCompile(`curl\s+(\S+)`)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if m := curlRe.FindStringSubmatch(host); len(m) == 2 {
			resp, err := http.Get(m[1])
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	ctx := WithOOB(context.Background(), srv)
	pg := page.FromURL(target.URL + "/ping?host=example.com")
	_, err := CmdInjectionBlind{}.Run(ctx, newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings := CmdInjectionBlind{}.Drain(ctx)
	if len(findings) == 0 {
		t.Fatalf("expected at least one OOB finding, registrations=%d",
			len(srv.Registrations("cmd-injection-blind")))
	}
	var got Finding
	for _, f := range findings {
		if strings.Contains(f.Title, "OOB-confirmed") {
			got = f
			break
		}
	}
	if got.Title == "" {
		t.Fatalf("no OOB-confirmed finding in results: %+v", findings)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
	if got.CWE != "CWE-78" {
		t.Errorf("CWE = %q, want CWE-78", got.CWE)
	}
	if !strings.Contains(got.Title, "host") {
		t.Errorf("title should name the param: %q", got.Title)
	}
}

func TestCmdInjectionBlindOOBDisabledWithoutServer(t *testing.T) {
	// No WithOOB in ctx: CmdInjectionBlind must not mint canaries
	// and Drain must be a no-op.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	pg := page.FromURL(target.URL + "/ping?host=example.com")
	_, err := CmdInjectionBlind{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := CmdInjectionBlind{}.Drain(context.Background())
	if len(got) != 0 {
		t.Errorf("Drain without OOB should return no findings, got %d", len(got))
	}
}

func TestSSRFOOBDisabledWithoutServer(t *testing.T) {
	// No WithOOB in ctx: SSRF must not mint canaries and Drain must be
	// a no-op so a passive scan doesn't accidentally emit blind
	// findings when OOB was never configured.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	pg := page.FromURL(target.URL + "/api/proxy")
	_, err := SSRF{}.Run(context.Background(), newTestClient(t), nil, pg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := SSRF{}.Drain(context.Background())
	if len(got) != 0 {
		t.Errorf("Drain without OOB should return no findings, got %d", len(got))
	}
}

// oobHostWrapper proxies the Builtin server but rewrites Register's
// returned Canary so the HTTPURL points at the listener's resolved
// bound address. The production Builtin embeds whatever host was
// passed to NewBuiltin; tests boot with "" and patch here.
type oobHostWrapper struct {
	b *oob.Builtin
}

func newOOBHostWrapper(b *oob.Builtin) *oobHostWrapper { return &oobHostWrapper{b: b} }

func (w *oobHostWrapper) Register(check string, extra map[string]string) oob.Canary {
	c := w.b.Register(check, extra)
	c.HTTPURL = "http://" + w.b.LocalAddr() + "/" + c.Token
	return c
}

func (w *oobHostWrapper) RegisterAsset(check, body, contentType string, extra map[string]string) oob.Canary {
	c := w.b.RegisterAsset(check, body, contentType, extra)
	c.HTTPURL = "http://" + w.b.LocalAddr() + "/" + c.Token
	return c
}

func (w *oobHostWrapper) Registrations(check string) []oob.Registration {
	regs := w.b.Registrations(check)
	for i := range regs {
		regs[i].Canary.HTTPURL = "http://" + w.b.LocalAddr() + "/" + regs[i].Canary.Token
	}
	return regs
}

func (w *oobHostWrapper) Hits(token string) []oob.Hit     { return w.b.Hits(token) }
func (w *oobHostWrapper) Start(ctx context.Context) error { return nil }
func (w *oobHostWrapper) Stop(ctx context.Context) error  { return nil }
func (w *oobHostWrapper) CallbackHost() string            { return w.b.LocalAddr() }
