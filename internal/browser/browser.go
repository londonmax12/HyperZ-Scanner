// Package browser is the headless-execution surface checks consume to test
// behaviors that only manifest at runtime - DOM XSS being the canonical
// case (the payload lives in location.hash or location.search and never
// touches the server, so static response inspection can't see it).
//
// The package hides chromedp behind a small Pool interface so:
//
//   - tests can substitute a fake Pool without launching a real browser
//   - a future engine swap (rod, go-rod/stealth, even a remote CDP target)
//     is one implementation change, not a fleet-wide refactor
//   - checks that want runtime execution import only `browser.Pool`, not
//     the cdproto / chromedp surface
//
// One Pool is created once per scan via NewChromedp and threaded through
// the scanner to checks via the context helpers in internal/checks. The
// scanner owns Close.
package browser

import (
	"context"
	"errors"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// BindingName is the name of the JS function the pool installs on every
// tab before navigation. A payload that achieves script execution calls
// this binding (e.g. `__hyperz_xss_pop('TOKEN')`); the call surfaces as a
// CDP runtime event the controller reads back. Exported so checks can
// embed the exact name in their payloads.
const BindingName = "__hyperz_xss_pop"

// Pool is the runtime-execution surface checks consume.
//
// Visit opens url in a fresh, isolated tab, waits up to settle for the
// installed binding to fire, and reports whether the canary token came
// through. (false, nil) is a clean miss - the page loaded but no payload
// executed; errors are reserved for navigation or browser-process
// failures, never for "no XSS fired."
//
// Implementations must be safe to call concurrently; the scan fans out
// many Visit calls in parallel.
type Pool interface {
	Visit(ctx context.Context, url, token string, settle time.Duration) (fired bool, err error)
	Close()
}

// chromedpPool runs Visit through a long-lived chromedp.Allocator (one
// browser process) and creates one tab per Visit. The tab is cancelled
// before Visit returns - tabs are cheap, leaking the parent process is
// not. A semaphore caps concurrent tabs so headless chrome doesn't OOM
// on a wide scan.
type chromedpPool struct {
	browserCtx context.Context
	cancel     context.CancelFunc
	sem        chan struct{}
}

// NewChromedp brings up a headless Chrome/Chromium process and returns a
// Pool that dispatches Visit calls against it. maxConcurrent caps
// simultaneous tabs; a sensible default fires when <=0 is passed.
//
// Returns an error only when the browser process fails to launch (no
// chrome binary on PATH, sandbox refused, etc). The caller should treat
// that as a hard opt-out of the JS path rather than a scan failure -
// the rest of the scanner does not depend on a Pool being present.
func NewChromedp(maxConcurrent int) (Pool, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		// The page is hostile by definition - don't let it hold the
		// process open with a beforeunload prompt.
		chromedp.Flag("disable-prompt-on-repost", true),
		// Container / CI ergonomics. --no-sandbox is required when the
		// process runs as root (typical in docker images); the scanner
		// is the trust boundary here, not chrome's renderer sandbox, so
		// dropping it is acceptable for an opt-in security tool.
		// --disable-dev-shm-usage avoids the 64MB /dev/shm cap that
		// causes chrome to crash on wide fan-out inside containers.
		chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	// NOTE: we deliberately do NOT pass --incognito. The whole-browser
	// incognito flag breaks chromedp's Target.createTarget path on
	// recent Chrome builds ("Failed to open new tab - no browser is
	// open"), and CDP's per-tab WithNewBrowserContext is unsupported on
	// the same builds, so neither variant of "per-tab fresh profile"
	// actually works. Per-tab cookie isolation also isn't load-bearing
	// for DOM XSS: each probe issues a new canary token via
	// ctx.browser.new_canary() and the binding listener matches on
	// token equality, so a stale binding fire from one tab can never
	// be misattributed to the next tab's payload. Tabs share the
	// default browser context's cookie jar - acceptable for the
	// runtime-execution checks we ship today.
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(browserCtx); err != nil {
		cancelBrowser()
		cancelAlloc()
		return nil, err
	}
	cancel := func() { cancelBrowser(); cancelAlloc() }
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	return &chromedpPool{
		browserCtx: browserCtx,
		cancel:     cancel,
		sem:        make(chan struct{}, maxConcurrent),
	}, nil
}

// errVisitTimedOut is the internal sentinel for "settle window elapsed
// without the binding firing." It never escapes Visit; callers see
// (false, nil) instead. Kept as a typed value so future Visit variants
// (e.g. an exec-and-screenshot helper) can distinguish "loaded clean"
// from "navigation never finished" if that distinction matters.
var errVisitTimedOut = errors.New("browser: visit settle window elapsed")

func (p *chromedpPool) Visit(ctx context.Context, url, token string, settle time.Duration) (bool, error) {
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return false, ctx.Err()
	}

	// tabCtx must derive from browserCtx so chromedp can reach the live
	// allocator / target handle; deriving directly from the caller's ctx
	// would sever that link. Instead, bridge caller cancellation into
	// tabCtx via a watchdog so a Ctrl-C on a long Navigate aborts the
	// in-flight tab instead of running to settle on a cancelled scan.
	tabCtx, cancel := chromedp.NewContext(p.browserCtx)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-stop:
		}
	}()

	// Buffered so the listener never blocks. Only the first binding call
	// is consumed - subsequent fires (sites that fire many onerror=
	// instances) are dropped, which is fine: we only need one proof.
	fired := make(chan string, 1)
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if be, ok := ev.(*runtime.EventBindingCalled); ok && be.Name == BindingName {
			select {
			case fired <- be.Payload:
			default:
			}
		}
	})

	// AddBinding must run before Navigate; once the page starts evaluating
	// scripts the binding has to already be exposed on window. chromedp
	// handles ordering as long as both actions sit in the same Run call.
	if err := chromedp.Run(tabCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return runtime.AddBinding(BindingName).Do(ctx)
		}),
		chromedp.Navigate(url),
	); err != nil {
		return false, err
	}

	select {
	case payload := <-fired:
		// Bindings deliver the JS string argument as-is, but chromedp
		// wraps it in JSON quoting; accept both shapes so a payload
		// written as `__hyperz_xss_pop('TOK')` matches whether CDP
		// hands us TOK or "TOK".
		return payload == token || payload == `"`+token+`"`, nil
	case <-time.After(settle):
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (p *chromedpPool) Close() { p.cancel() }
