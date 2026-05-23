// Package crawler discovers URLs by fetching seed pages in parallel and
// extracting links from their HTML. Discovered URLs are streamed to an
// output channel so downstream scanners can process them as they're found.
package crawler

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
	"github.com/londonball/hyperz/internal/scope"
)

const defaultMaxBodyBytes = 5 << 20 // 5 MiB

// Config controls how the crawler walks links. The host allowlist and depth
// cap live on the Scope, not here - pass the same Scope to the scanner so
// crawl boundaries and check boundaries can't drift apart.
type Config struct {
	Workers      int          // concurrent fetchers; 0 → 8
	MaxPages     int          // 0 → unlimited
	MaxBodyBytes int64        // per-page body cap; 0 → 5 MiB
	Scope        *scope.Scope // nil → no host/port/path/depth gating
	// APIDiscovery enables two behaviors: (1) probing a fixed list of
	// well-known OpenAPI / Swagger paths against each seed origin at
	// startup, and (2) when a fetched URL returns a JSON/YAML body that
	// parses as a spec, queueing every documented operation as a target.
	// Without this the crawler skips non-HTML responses and never sees
	// API surface that isn't linked from a rendered page.
	APIDiscovery bool
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
		pending.Add(1)
		go func() {
			select {
			case <-ctx.Done():
				finish()
			case work <- item{url: canonical, depth: depth}:
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < c.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range work {
				c.process(ctx, it, out, submit, recordSpecOps, takeSpecOps)
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
) {
	// emit drops a Page onto out, respecting ctx cancellation. Returns
	// false if the send was abandoned so the caller can stop processing.
	// Any spec ops registered for this URL by an earlier spec parse are
	// attached just before the send so input-fuzzing checks see them.
	emit := func(p page.Page) bool {
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
