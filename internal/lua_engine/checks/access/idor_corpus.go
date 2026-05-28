package access

import (
	"net/url"
	"strings"
	"sync"

	"github.com/londonmax12/hyperz/internal/lua_engine"
	"github.com/londonmax12/hyperz/internal/page"
)

// Corpus is the scan-lifetime store the IDOR check consults to (a)
// classify a sink's value against built-in and learned patterns, and
// (b) generate tampering candidates drawn from values seen elsewhere in
// the same scan. One *IDOR instance owns one *Corpus for the duration
// of a scan; concurrent page workers ingest into it under a single
// mutex.
//
// Memory is bounded everywhere: ringBufs cap per-key history at a
// small constant, and shape clustering tracks aggregate counts rather
// than full sample lists. A 10,000-page scan stays under a megabyte
// of corpus state on a typical site.
type Corpus struct {
	mu              sync.Mutex
	valuesByParam   map[string]*ringBuf
	valuesByPattern map[string]*ringBuf
	valuesByShape   map[string]*ringBuf
	shapeRecords    map[string]*shapeRecord
	learned         []Pattern
}

// shapeRecord tracks the cluster of values agreeing on one shape
// signature. count includes every ingested value (including dups); the
// distinct-param set is what drives promotion - a shape that appears
// only under one param name is more likely a coincidence than a real
// identifier format, so promotion requires at least two distinct
// param names agree on the shape.
type shapeRecord struct {
	count    int
	params   map[string]struct{}
	promoted bool
}

// ringBuf is a fixed-capacity FIFO over strings. Newer entries push
// older ones out so corpus memory stays bounded regardless of crawl
// length. snapshot() returns values in insertion order (oldest first),
// which keeps Pattern.Generate output deterministic for any fixed
// corpus state.
type ringBuf struct {
	cap  int
	data []string
	seen map[string]struct{}
}

func newRingBuf(cap int) *ringBuf {
	return &ringBuf{cap: cap, seen: make(map[string]struct{})}
}

func (r *ringBuf) push(v string) {
	if v == "" {
		return
	}
	if _, ok := r.seen[v]; ok {
		return
	}
	if len(r.data) >= r.cap {
		drop := r.data[0]
		r.data = r.data[1:]
		delete(r.seen, drop)
	}
	r.data = append(r.data, v)
	r.seen[v] = struct{}{}
}

func (r *ringBuf) snapshot() []string {
	out := make([]string, len(r.data))
	copy(out, r.data)
	return out
}

const (
	// corpusParamCap bounds per-param-name value history. 32 is enough
	// to surface real diversity (paginated lists of objects rarely
	// expose more than a few dozen IDs per param) without growing the
	// corpus unboundedly on a long crawl.
	corpusParamCap = 32
	// corpusPatternCap bounds per-pattern history. Larger than the
	// per-param cap because Generate draws across params - a numeric
	// id may surface on /users, /orders, /tickets, and we want a
	// sample drawn from all of them.
	corpusPatternCap = 64
	// corpusShapeCap bounds per-shape history. Used by learned
	// patterns' Generate to find same-shape values; the cap is small
	// because once we've promoted a shape we mostly rely on
	// renderShape to fabricate variants.
	corpusShapeCap = 32

	// learnMinSamples is how many ingested values agreeing on one shape
	// before the engine considers promoting it. Set to 3 so we don't
	// learn off two-sample coincidences.
	learnMinSamples = 3
	// learnMinDistinctParams gates promotion further: at least this
	// many distinct param names must have produced a value of the
	// shape. A shape that only ever appears under one param is more
	// likely a format quirk of that field than a reusable family.
	learnMinDistinctParams = 2
)

// NewCorpus returns an empty Corpus. Callers (the IDOR check) keep one
// for the scan lifetime and call IngestPage at the top of every Run.
func NewCorpus() *Corpus {
	return &Corpus{
		valuesByParam:   make(map[string]*ringBuf),
		valuesByPattern: make(map[string]*ringBuf),
		valuesByShape:   make(map[string]*ringBuf),
		shapeRecords:    make(map[string]*shapeRecord),
	}
}

// IngestPage walks every sink discoverable on p and folds the wire
// values into the corpus: per-param history, per-pattern history,
// per-shape clustering. Path segments that look like identifiers are
// ingested too so an IDOR check seeing /api/users/42 learns about `42`
// even when the crawler didn't expose it as a query parameter.
//
// Safe to call concurrently from multiple page workers.
func (c *Corpus) IngestPage(p page.Page) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range lua_engine.SinksFor(p) {
		c.ingestLocked(s.Name, s.Value)
	}
	if u, err := url.Parse(p.URL); err == nil {
		for _, seg := range strings.Split(u.EscapedPath(), "/") {
			if seg == "" {
				continue
			}
			decoded, err := url.PathUnescape(seg)
			if err != nil {
				continue
			}
			c.ingestLocked("__path__", decoded)
		}
	}
}

// Ingest is the single-value entry point exposed for tests; production
// code uses IngestPage. name should be the lowercased param name (or
// "__path__" for path segments); value is the wire value.
func (c *Corpus) Ingest(name, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ingestLocked(name, value)
}

func (c *Corpus) ingestLocked(name, value string) {
	if value == "" {
		return
	}
	name = strings.ToLower(name)
	if _, ok := c.valuesByParam[name]; !ok {
		c.valuesByParam[name] = newRingBuf(corpusParamCap)
	}
	c.valuesByParam[name].push(value)

	p := classifyValue(name, value, c.learned)
	if p != nil {
		if _, ok := c.valuesByPattern[p.Name]; !ok {
			c.valuesByPattern[p.Name] = newRingBuf(corpusPatternCap)
		}
		c.valuesByPattern[p.Name].push(value)
		// A value already covered by a built-in is not a candidate for
		// learning a new shape - we already have a pattern for it.
		if !p.Learned {
			return
		}
	}

	shape := ShapeSignature(value)
	if shape == "" {
		return
	}
	rec, ok := c.shapeRecords[shape]
	if !ok {
		rec = &shapeRecord{params: make(map[string]struct{})}
		c.shapeRecords[shape] = rec
	}
	rec.count++
	rec.params[name] = struct{}{}
	if _, ok := c.valuesByShape[shape]; !ok {
		c.valuesByShape[shape] = newRingBuf(corpusShapeCap)
	}
	c.valuesByShape[shape].push(value)

	if !rec.promoted && rec.count >= learnMinSamples && len(rec.params) >= learnMinDistinctParams {
		c.learned = append(c.learned, learnedPatternFromShape(shape))
		rec.promoted = true
	}
}

// Classify returns the pattern that best fits (name, value), or nil if
// the value doesn't look like an identifier the check should probe.
// Considers learned patterns alongside built-ins.
func (c *Corpus) Classify(name, value string) *Pattern {
	c.mu.Lock()
	learned := make([]Pattern, len(c.learned))
	copy(learned, c.learned)
	c.mu.Unlock()
	return classifyValue(strings.ToLower(name), value, learned)
}

// LearnedPatterns returns a snapshot of every shape that crossed the
// promotion threshold during the scan. Exposed for tests and for
// findings that want to attribute a detection to a learned shape.
func (c *Corpus) LearnedPatterns() []Pattern {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Pattern, len(c.learned))
	copy(out, c.learned)
	return out
}

// valuesForPattern returns the per-pattern history snapshot. Held
// inside Pattern.Generate closures; the lock is taken only for the
// snapshot so Generate itself runs lock-free.
func (c *Corpus) valuesForPattern(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rb, ok := c.valuesByPattern[name]; ok {
		return rb.snapshot()
	}
	return nil
}

// valuesForShape returns the per-shape history snapshot. Used by
// learned patterns' Generate to surface real same-shape values from
// elsewhere in the scan before falling back to renderShape.
func (c *Corpus) valuesForShape(shape string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rb, ok := c.valuesByShape[shape]; ok {
		return rb.snapshot()
	}
	return nil
}

// ValuesForParam returns the per-param history snapshot. Exposed for
// tests; the IDOR check itself draws candidates by pattern, not by
// param.
func (c *Corpus) ValuesForParam(name string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rb, ok := c.valuesByParam[strings.ToLower(name)]; ok {
		return rb.snapshot()
	}
	return nil
}
