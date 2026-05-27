// Package crawler discovers URLs by fetching seed pages in parallel and
// extracting links from their HTML. Discovered URLs are streamed to an
// output channel so downstream scanners can process them as they're found.
package crawler

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
	"github.com/londonmax12/hyperz/internal/scope"
)

const defaultMaxBodyBytes = 5 << 20 // 5 MiB

// Config controls how the crawler walks links. The host allowlist and depth
// cap live on the Scope, not here - pass the same Scope to the scanner so
// crawl boundaries and check boundaries can't drift apart.
type Config struct {
	Workers      int          // concurrent fetchers; 0 â†’ 8
	MaxPages     int          // 0 â†’ unlimited
	MaxBodyBytes int64        // per-page body cap; 0 â†’ 5 MiB
	Scope        *scope.Scope // nil â†’ no host/port/path/depth gating
	// APIDiscovery enables two behaviors: (1) probing a fixed list of
	// well-known OpenAPI / Swagger paths against each seed origin at
	// startup, and (2) when a fetched URL returns a JSON/YAML body that
	// parses as a spec, queueing every documented operation as a target.
	// Without this the crawler skips non-HTML responses and never sees
	// API surface that isn't linked from a rendered page.
	APIDiscovery bool
	// Pollute opts the crawler into state-mutating discovery: submit
	// select-driven navigation forms (a <form method="POST"> whose only
	// non-trivial input is a <select>, the pattern used by bWAPP's
	// portal, lots of CMS admin panels, and old PHP control panels) one
	// option at a time and enqueue every distinct redirect target the
	// server points us at. Off by default because POSTing forms can
	// trigger side effects we can't reverse - turn it on only against
	// targets you have authorization to mutate.
	Pollute bool
}

type Crawler struct {
	cfg     Config
	client  *httpclient.Client
	onError func(target string, err error)
}

type Option func(*Crawler)

func WithErrorHandler(fn func(string, error)) Option {
	return func(c *Crawler) { c.onError = fn }
}

func New(client *httpclient.Client, cfg Config, opts ...Option) *Crawler {
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	c := &Crawler{cfg: cfg, client: client}
	for _, o := range opts {
		o(c)
	}
	return c
}

type item struct {
	url   string
	depth int
	// isSpec marks URLs whose path heuristically looks like an
	// OpenAPI / Swagger document (well-known suffix or .json / .yaml
	// extension; see looksLikeSpec). The worker uses this to bracket
	// the item in the specsInFlight WaitGroup so a sibling worker
	// emitting a non-spec page can wait for late-arriving recordSpecOps
	// to land before it calls takeSpecOps. Without this synchronization,
	// link discovery enqueuing /api/foo just ahead of an OpenAPI parse
	// that covers /api/foo would lose the operations to the dedupe.
	isSpec bool
}

// Crawl visits seeds and any reachable links permitted by the configured
// Scope, emitting one page.Page per unique URL onto out. The Page carries
// the fetched URL's status, headers, body (capped at MaxBodyBytes), and
// extracted forms so downstream checks don't have to re-fetch. out is
// closed when crawling completes or ctx is canceled.
//
// A Page is also emitted for URLs that couldn't be fetched (network
// error, scope-permitted-but-redirect-only, etc.); those carry the URL
// only and leave Status / Headers / Body / Forms zero-valued, with
// Fetched=true so downstream helpers (checks/ensureResponse) treat the
// URL as already-tried and don't re-issue per-check GETs against a host
// the crawler already failed on.
func (c *Crawler) Crawl(ctx context.Context, seeds []string, out chan<- page.Page) error {
	defer close(out)

	work := make(chan item, c.cfg.Workers*2)
	var (
		pending   atomic.Int64
		queued    atomic.Int64
		closeOnce sync.Once
		visited   sync.Map
		// specOpsMu guards specOps. specOps maps a spec-derived URL to
		// the operations a parsed OpenAPI / Swagger document declared
		// for it. The map is written when a worker parses a spec body
		// (one or more operations per documented URL) and read when a
		// worker later emits the Page for that URL, so the input-fuzzing
		// surface declared by the spec rides on the Page that downstream
		// checks already see. Concurrent workers may parse different
		// specs that overlap on a URL; appends merge their contributions.
		specOpsMu sync.Mutex
		specOps   = map[string][]page.SpecOp{}
		// specsInFlight tracks queued + in-process items whose URL path
		// looks like a spec document. emit() for non-spec pages calls
		// Wait() so that any recordSpecOps the in-flight spec parses
		// produce is visible by the time the page's takeSpecOps runs.
		// Without it, link discovery racing an OpenAPI parse on the
		// same operation URL would emit the page with empty SpecOps,
		// and proto-pollution / race-condition / any other check that
		// reads p.SpecOps would silently see no input surface.
		specsInFlight sync.WaitGroup
	)

	closeWork := func() { closeOnce.Do(func() { close(work) }) }

	// finish decrements the in-flight counter and closes the work channel
	// once nothing is outstanding. Called once per successful submit.
	finish := func() {
		if pending.Add(-1) == 0 {
			closeWork()
		}
	}

	// recordSpecOps registers the operations a parsed spec declared at
	// canonical URL, keyed by the URL the crawler will submit. Called
	// before submit() so the next worker to fetch this URL sees the
	// ops when it goes to emit. Overlapping specs (rare; same URL from
	// two different documents) accumulate rather than replace.
	recordSpecOps := func(canonical string, ops []page.SpecOp) {
		if len(ops) == 0 {
			return
		}
		specOpsMu.Lock()
		specOps[canonical] = append(specOps[canonical], ops...)
		specOpsMu.Unlock()
	}

	// takeSpecOps returns and removes any spec ops registered for the
	// URL. The map entry is dropped because each URL gets emitted once;
	// keeping the entry around would just grow the map for the rest of
	// the crawl.
	takeSpecOps := func(canonical string) []page.SpecOp {
		specOpsMu.Lock()
		defer specOpsMu.Unlock()
		ops, ok := specOps[canonical]
		if !ok {
			return nil
		}
		delete(specOps, canonical)
		return ops
	}

	var submit func(rawurl string, depth int)
	submit = func(rawurl string, depth int) {
		if !c.cfg.Scope.AllowsDepth(depth) {
			return
		}
		u, err := url.Parse(rawurl)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		if !c.cfg.Scope.Allows(u) {
			return
		}
		u.Fragment = ""
		canonical := u.String()
		if _, loaded := visited.LoadOrStore(canonical, struct{}{}); loaded {
			return
		}
		if c.cfg.MaxPages > 0 && queued.Add(1) > int64(c.cfg.MaxPages) {
			return
		}
		// Path-only heuristic: contentType is unknown at submit time, but
		// the well-known spec paths plus any .json / .yaml extension or
		// /api-docs / /swagger / /openapi suffix are recognizable from the
		// URL alone. False positives (a /data.json that turns out not to
		// be a spec) only cost a single specsInFlight slot; the per-item
		// teardown decrements it after process() returns regardless.
		isSpec := looksLikeSpec("", u.Path)
		pending.Add(1)
		if isSpec {
			specsInFlight.Add(1)
			// Spec items run on their own goroutine instead of the
			// shared worker pool. If all general workers ended up at
			// emit() waiting on specsInFlight while the spec items
			// were still queued for the same pool, we'd deadlock; a
			// dedicated goroutine per spec guarantees forward progress.
			// The worker count is irrelevant - well-known spec paths
			// are bounded (~12 per origin) and link-discovered specs
			// are rare, so we are not at risk of goroutine blowup.
			go func() {
				if ctx.Err() == nil {
					c.process(ctx, item{url: canonical, depth: depth, isSpec: true},
						out, submit, recordSpecOps, takeSpecOps, specsInFlight.Wait)
				}
				specsInFlight.Done()
				finish()
			}()
			return
		}
		go func() {
			select {
			case <-ctx.Done():
				finish()
			case work <- item{url: canonical, depth: depth, isSpec: false}:
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < c.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range work {
				c.process(ctx, it, out, submit, recordSpecOps, takeSpecOps, specsInFlight.Wait)
				finish()
			}
		}()
	}

	// Bootstrap: hold a virtual "submission in progress" slot so workers
	// don't see pending=0 mid-seeding and close work prematurely.
	pending.Add(1)
	probedOrigins := map[string]struct{}{}
	for _, s := range seeds {
		submit(s, 0)
		if !c.cfg.APIDiscovery {
			continue
		}
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		if _, ok := probedOrigins[origin]; ok {
			continue
		}
		probedOrigins[origin] = struct{}{}
		for _, p := range wellKnownSpecPaths {
			submit(origin+p, 0)
		}
	}
	if pending.Add(-1) == 0 {
		closeWork()
	}

	wg.Wait()
	return ctx.Err()
}

func (c *Crawler) process(
	ctx context.Context,
	it item,
	out chan<- page.Page,
	submit func(string, int),
	recordSpecOps func(string, []page.SpecOp),
	takeSpecOps func(string) []page.SpecOp,
	waitSpecsInFlight func(),
) {
	// emit drops a Page onto out, respecting ctx cancellation. Returns
	// false if the send was abandoned so the caller can stop processing.
	// Any spec ops registered for this URL by an earlier spec parse are
	// attached just before the send so input-fuzzing checks see them.
	//
	// For non-spec items, emit first waits for every spec parse the
	// crawler currently has in flight to complete. A spec parse calls
	// recordSpecOps before returning, so by the time the WaitGroup
	// drains, any SpecOps that would cover this URL are guaranteed to
	// be visible to takeSpecOps. Without the wait, link-discovered
	// /api/foo could be emitted in the gap between the OpenAPI worker
	// finishing the fetch and finishing the parse, dropping the
	// JSON-body sinks the openapi spec was about to declare for it.
	// Spec items skip the wait so they can't block each other; their
	// own emit just publishes the spec page itself.
	emit := func(p page.Page) bool {
		if !it.isSpec {
			waitSpecsInFlight()
		}
		if ops := takeSpecOps(p.URL); len(ops) > 0 {
			p.SpecOps = ops
		}
		select {
		case <-ctx.Done():
			return false
		case out <- p:
			return true
		}
	}

	resp, err := c.client.Get(ctx, it.url)
	if err != nil {
		if c.onError != nil {
			c.onError(it.url, err)
		}
		// Surface the URL anyway so the scanner / passive checks still see
		// it - matches the pre-Page behavior where every queued URL was
		// emitted before fetching. Fetched=true so ensureResponse won't
		// re-GET the same dead host once per passive check.
		emit(page.Page{URL: it.url, Fetched: true})
		return
	}
	defer resp.Body.Close()

	body, err := httpclient.ReadBody(resp, c.cfg.MaxBodyBytes)
	if err != nil {
		if c.onError != nil {
			c.onError(it.url, err)
		}
		emit(page.Page{
			URL:     it.url,
			Status:  resp.StatusCode,
			Headers: resp.Header,
			Fetched: true,
		})
		return
	}

	base, err := url.Parse(it.url)
	if err != nil {
		emit(page.Page{
			URL:     it.url,
			Status:  resp.StatusCode,
			Headers: resp.Header,
			Body:    body,
			Fetched: true,
		})
		return
	}

	ct := resp.Header.Get("Content-Type")
	p := page.Page{
		URL:     it.url,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    body,
		Fetched: true,
	}

	if strings.Contains(strings.ToLower(ct), "text/html") {
		links, forms := extractAll(base, body)
		p.Forms = forms
		if !emit(p) {
			return
		}
		if !c.cfg.Scope.AllowsDepth(it.depth + 1) {
			return
		}
		for _, link := range links {
			submit(link, it.depth+1)
		}
		if c.cfg.Pollute {
			c.walkSelectForms(ctx, forms, it.depth+1, submit)
		}
		return
	}

	// Non-HTML: emit unchanged (no forms), then optionally feed the body
	// to the OpenAPI / Swagger extractor when API discovery is on.
	if !emit(p) {
		return
	}
	if !c.cfg.APIDiscovery {
		return
	}
	if !looksLikeSpec(ct, base.Path) {
		return
	}
	if !c.cfg.Scope.AllowsDepth(it.depth + 1) {
		return
	}
	// Group ops by URL so the per-URL bucket lands as one stash. submit
	// dedups on URL, so we only push each distinct URL once even when
	// the spec describes multiple methods on it.
	byURL := map[string][]page.SpecOp{}
	for _, op := range extractAPIOperations(body, base) {
		byURL[op.URL] = append(byURL[op.URL], op)
	}
	for u, ops := range byURL {
		recordSpecOps(u, ops)
		submit(u, it.depth+1)
	}
}

// walkSelectForms POSTs every option of every select-driven navigation
// form on the page and queues the redirect target each submission yields.
// Only fires when Config.Pollute is true. Forms are gated by
// isSelectNavForm so we never blind-submit something that looks like a
// destructive action (visible text/file inputs disqualify it).
//
// We deliberately don't enqueue the POST's own response body, only the
// Location header of a 3xx. Two reasons: (1) the POST may have mutated
// state and refetching it as a GET target risks running active checks
// against side-effected pages, and (2) the redirect target is what a
// real user would land on, which is what we want to scan.
func (c *Crawler) walkSelectForms(
	ctx context.Context,
	forms []page.Form,
	depth int,
	submit func(string, int),
) {
	for _, form := range forms {
		sel, ok := isSelectNavForm(form)
		if !ok {
			continue
		}
		seenOpt := map[string]struct{}{}
		for _, opt := range sel.Options {
			if _, dup := seenOpt[opt]; dup {
				continue
			}
			seenOpt[opt] = struct{}{}
			body := buildSelectFormBody(form, sel.Name, opt)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, form.Action,
				strings.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := c.client.DoNoFollow(ctx, req)
			if err != nil {
				if c.onError != nil {
					c.onError(form.Action, err)
				}
				continue
			}
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if loc == "" {
				continue
			}
			base, perr := url.Parse(form.Action)
			if perr != nil {
				continue
			}
			ref, perr := url.Parse(loc)
			if perr != nil {
				continue
			}
			target := base.ResolveReference(ref)
			if target.String() == form.Action {
				// Server bounced back to the form (a "no-op" option like
				// a separator or category header). Skip.
				continue
			}
			submit(target.String(), depth)
		}
	}
}

// isSelectNavForm decides whether form looks like a select-driven
// navigation form safe to enumerate. Heuristic: exactly one named
// <select> with options, plus any number of hidden / submit / button
// inputs, and no visible text-bearing controls (text, email, password,
// search, tel, url, number, textarea, file). A form with a visible
// field is almost certainly a real submission, not nav.
func isSelectNavForm(form page.Form) (page.FormInput, bool) {
	if strings.ToUpper(form.Method) != "POST" || form.Action == "" {
		return page.FormInput{}, false
	}
	var sel page.FormInput
	selects := 0
	for _, in := range form.Inputs {
		switch in.Type {
		case "select":
			selects++
			sel = in
		case "hidden", "submit", "reset", "image", "button":
			// safe to carry along
		default:
			// any visible / data-bearing control disqualifies the form
			return page.FormInput{}, false
		}
	}
	if selects != 1 || len(sel.Options) == 0 || sel.Name == "" {
		return page.FormInput{}, false
	}
	return sel, true
}

// buildSelectFormBody builds the urlencoded body for a select-form
// submission: the select's name pinned to optValue, every hidden input
// carried verbatim, and every submit button pinned to its default value
// (server-side handlers often branch on the button name to decide what
// the form does).
func buildSelectFormBody(form page.Form, selName, optValue string) string {
	v := url.Values{}
	v.Set(selName, optValue)
	for _, in := range form.Inputs {
		if in.Name == "" || in.Name == selName {
			continue
		}
		switch in.Type {
		case "hidden":
			v.Set(in.Name, in.Value)
		case "submit", "button", "image":
			val := in.Value
			if val == "" {
				val = "submit"
			}
			v.Set(in.Name, val)
		}
	}
	return v.Encode()
}
