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
// Scope, emitting every unique URL it queues onto out. out is closed when
// crawling completes or ctx is canceled.
func (c *Crawler) Crawl(ctx context.Context, seeds []string, out chan<- string) error {
	defer close(out)

	work := make(chan item, c.cfg.Workers*2)
	var (
		pending   atomic.Int64
		queued    atomic.Int64
		closeOnce sync.Once
		visited   sync.Map
	)

	closeWork := func() { closeOnce.Do(func() { close(work) }) }

	// finish decrements the in-flight counter and closes the work channel
	// once nothing is outstanding. Called once per successful submit.
	finish := func() {
		if pending.Add(-1) == 0 {
			closeWork()
		}
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
				c.process(ctx, it, out, submit)
				finish()
			}
		}()
	}

	// Bootstrap: hold a virtual "submission in progress" slot so workers
	// don't see pending=0 mid-seeding and close work prematurely.
	pending.Add(1)
	for _, s := range seeds {
		submit(s, 0)
	}
	if pending.Add(-1) == 0 {
		closeWork()
	}

	wg.Wait()
	return ctx.Err()
}

func (c *Crawler) process(ctx context.Context, it item, out chan<- string, submit func(string, int)) {
	select {
	case <-ctx.Done():
		return
	case out <- it.url:
	}

	if !c.cfg.Scope.AllowsDepth(it.depth + 1) {
		return
	}

	resp, err := c.client.Get(ctx, it.url)
	if err != nil {
		if c.onError != nil {
			c.onError(it.url, err)
		}
		return
	}
	defer resp.Body.Close()

	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return
	}

	body, err := httpclient.ReadBody(resp, c.cfg.MaxBodyBytes)
	if err != nil {
		if c.onError != nil {
			c.onError(it.url, err)
		}
		return
	}

	base, err := url.Parse(it.url)
	if err != nil {
		return
	}
	for _, link := range extractLinks(base, body) {
		submit(link, it.depth+1)
	}
}
