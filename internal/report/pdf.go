package report

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/londonmax12/hyperz/internal/core"
	"github.com/londonmax12/hyperz/internal/fingerprint"
	"github.com/londonmax12/hyperz/internal/httpclient"
)

// PDF reporter emits a minimal, dependency-free PDF 1.4 document using
// Helvetica and Helvetica-Bold from the 14 standard fonts every viewer
// ships, so no font embedding is required. Streams are uncompressed so
// the rendered text stays greppable in the raw bytes - useful for tests.

const (
	pdfPageW      = 612.0 // US Letter, points
	pdfPageH      = 792.0
	pdfMarginX    = 54.0
	pdfMarginTop  = 72.0
	pdfMarginBot  = 60.0
	pdfBodyTop    = pdfPageH - pdfMarginTop
	pdfBodyBottom = pdfMarginBot
	pdfBodyLeft   = pdfMarginX
	pdfBodyRight  = pdfPageW - pdfMarginX
	pdfBodyWidth  = pdfBodyRight - pdfBodyLeft

	pdfSizeChrome = 8.5
	pdfSizeBase   = 10.0
	pdfSizeH3     = 12.0
	pdfSizeH2     = 16.0
	pdfSizeH1     = 26.0

	pdfWrapChars = 92

	fontReg  = "F1"
	fontBold = "F2"
)

type pdfReporter struct{}

func (pdfReporter) Write(ctx context.Context, w io.Writer, in <-chan core.Finding, meta Metadata) error {
	findings := drain(ctx, in)
	d := newPDFDoc()
	d.renderReport(findings, meta)
	d.addFooters()
	return d.serialize(w)
}

type pdfDoc struct {
	pages []*bytes.Buffer
	y     float64 // baseline y the next writeLine will descend from
}

func newPDFDoc() *pdfDoc {
	d := &pdfDoc{}
	d.newPage()
	return d
}

func (d *pdfDoc) newPage() {
	d.pages = append(d.pages, &bytes.Buffer{})
	d.y = pdfBodyTop
	d.drawHeader()
}

func (d *pdfDoc) current() *bytes.Buffer { return d.pages[len(d.pages)-1] }

// --- low-level primitives (no cursor effect) ---

func (d *pdfDoc) text(x, y float64, s, font string, size, r, g, b float64) {
	textInto(d.current(), x, y, s, font, size, r, g, b)
}

func textInto(p *bytes.Buffer, x, y float64, s, font string, size, r, g, b float64) {
	fmt.Fprintf(p, "BT\n/%s %.2f Tf\n%.3f %.3f %.3f rg\n%.2f %.2f Td\n(%s) Tj\nET\n",
		font, size, r, g, b, x, y, pdfEscape(s))
}

func (d *pdfDoc) fillRect(x, y, w, h, r, g, b float64) {
	fmt.Fprintf(d.current(), "%.3f %.3f %.3f rg\n%.2f %.2f %.2f %.2f re f\n",
		r, g, b, x, y, w, h)
}

func (d *pdfDoc) hline(x1, x2, y, lw, r, g, b float64) {
	fmt.Fprintf(d.current(), "%.3f %.3f %.3f RG\n%.2f w\n%.2f %.2f m %.2f %.2f l S\n",
		r, g, b, lw, x1, y, x2, y)
}

// drawHeader paints the running header at the top of the current page.
func (d *pdfDoc) drawHeader() {
	y := pdfPageH - pdfMarginTop + 18
	d.text(pdfBodyLeft, y, "hyperz scan report", fontBold, pdfSizeChrome, 0.45, 0.45, 0.45)
	stamp := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	rx := pdfBodyRight - approxWidth(stamp, pdfSizeChrome)
	if rx < pdfBodyLeft {
		rx = pdfBodyLeft
	}
	d.text(rx, y, stamp, fontReg, pdfSizeChrome, 0.55, 0.55, 0.55)
	d.hline(pdfBodyLeft, pdfBodyRight, y-4, 0.5, 0.80, 0.80, 0.80)
}

// addFooters runs after all pages are laid out so we know totals.
func (d *pdfDoc) addFooters() {
	total := len(d.pages)
	for i, p := range d.pages {
		s := fmt.Sprintf("page %d of %d", i+1, total)
		x := pdfBodyLeft + (pdfBodyWidth-approxWidth(s, pdfSizeChrome))/2
		textInto(p, x, pdfMarginBot-24, s, fontReg, pdfSizeChrome, 0.55, 0.55, 0.55)
	}
}

// --- cursor model ---

func (d *pdfDoc) ensureSpace(h float64) {
	if d.y-h < pdfBodyBottom {
		d.newPage()
	}
}

func (d *pdfDoc) writeLine(s, font string, size, r, g, b float64) {
	d.writeLineAt(0, s, font, size, r, g, b)
}

func (d *pdfDoc) writeLineAt(indent float64, s, font string, size, r, g, b float64) {
	leading := size * 1.35
	d.ensureSpace(leading)
	d.y -= leading
	d.text(pdfBodyLeft+indent, d.y, s, font, size, r, g, b)
}

func (d *pdfDoc) writeWrapped(s string, indent float64, font string, size, r, g, b float64) {
	for _, line := range pdfWrap(s, pdfWrapChars) {
		d.writeLineAt(indent, line, font, size, r, g, b)
	}
}

func (d *pdfDoc) gap(h float64) { d.y -= h }

// --- report layout ---

var severityOrder = []core.Severity{
	core.SeverityCritical,
	core.SeverityHigh,
	core.SeverityMedium,
	core.SeverityLow,
	core.SeverityInfo,
}

func (d *pdfDoc) renderReport(findings []core.Finding, meta Metadata) {
	d.renderCover(findings, meta.Diff)
	d.renderStacks(meta.Stacks)
	d.renderBudget(meta.Budget)
	if len(findings) == 0 {
		return
	}

	// Group by (severity, check) so a check that fires on N URLs renders as
	// one block - shared title/refs/fix/detail printed once, a per-URL
	// "affected" list, and a single sample evidence. The same idea as the
	// security-headers check folding many missing-header facets into one
	// finding, applied at report time across instances. Without this a
	// 671-finding scan blows out to 831 PDF pages.
	bySev := map[core.Severity][]checkGroup{}
	sevCounts := map[core.Severity]int{}
	for _, g := range groupFindings(findings) {
		bySev[g.Severity] = append(bySev[g.Severity], g)
		sevCounts[g.Severity] += len(g.All)
	}

	for _, sev := range severityOrder {
		bucket := bySev[sev]
		if len(bucket) == 0 {
			continue
		}
		d.newPage()
		d.renderSeverityHeading(sev, sevCounts[sev])
		for i, g := range bucket {
			d.renderCheckGroup(g)
			if i < len(bucket)-1 {
				d.separator()
			}
		}
	}
}

// checkGroup aggregates findings that share both severity and check name.
// Rep holds the first observed finding and supplies the shared fields
// (title, CWE, OWASP, remediation, detail, sample evidence). All preserves
// every instance in arrival order so per-URL variation - and per-instance
// diff status - can still be listed.
type checkGroup struct {
	Severity core.Severity
	Check    string
	Rep      core.Finding
	All      []core.Finding
}

func groupFindings(findings []core.Finding) []checkGroup {
	type key struct {
		sev   core.Severity
		check string
	}
	idx := map[key]int{}
	var out []checkGroup
	for _, f := range findings {
		k := key{f.Severity, f.Check}
		if i, ok := idx[k]; ok {
			out[i].All = append(out[i].All, f)
			continue
		}
		idx[k] = len(out)
		out = append(out, checkGroup{
			Severity: f.Severity,
			Check:    f.Check,
			Rep:      f,
			All:      []core.Finding{f},
		})
	}
	return out
}

// renderBudget adds a "Request budget" page when a scan-wide budget was in
// effect. Skipped when both knobs were off so the section never appears as
// a phantom "0 / 0" page.
func (d *pdfDoc) renderBudget(budget *httpclient.Budget) {
	if budget == nil {
		return
	}
	s := budget.Snapshot()
	if s.Max == 0 && s.GlobalRPS == 0 {
		return
	}
	d.newPage()
	d.writeLine("Request budget", fontBold, pdfSizeH2, 0.10, 0.10, 0.10)
	d.gap(4)
	d.hline(pdfBodyLeft, pdfBodyRight, d.y, 0.5, 0.85, 0.85, 0.85)
	d.gap(8)
	if s.Max > 0 {
		line := fmt.Sprintf("requests: %d / %d", s.Requests, s.Max)
		if s.Exhausted {
			line += fmt.Sprintf("  (exhausted at %s)", s.ExhaustedAt.UTC().Format(time.RFC3339))
		}
		d.writeLine(line, fontReg, pdfSizeBase, 0, 0, 0)
	} else {
		d.writeLine(fmt.Sprintf("requests: %d", s.Requests), fontReg, pdfSizeBase, 0, 0, 0)
	}
	if s.GlobalRPS > 0 {
		d.writeLine(fmt.Sprintf("global rate: %g rps", s.GlobalRPS), fontReg, pdfSizeBase, 0, 0, 0)
	}
}

// renderStacks adds a "Detected stacks" page after the cover. Each row is
// "host - server=â€¦ language=â€¦ â€¦" so the PDF stays single-column without
// reaching for table primitives we don't have.
func (d *pdfDoc) renderStacks(stacks map[string]*fingerprint.Stack) {
	if len(stacks) == 0 {
		return
	}
	d.newPage()
	d.writeLine("Detected stacks", fontBold, pdfSizeH2, 0.10, 0.10, 0.10)
	d.gap(4)
	d.hline(pdfBodyLeft, pdfBodyRight, d.y, 0.5, 0.85, 0.85, 0.85)
	d.gap(8)
	for _, host := range sortedHosts(stacks) {
		s := stacks[host]
		d.writeLine(host, fontBold, pdfSizeBase, 0.10, 0.10, 0.10)
		d.writeWrapped(s.Summary(), 12, fontReg, pdfSizeBase, 0.25, 0.25, 0.25)
		d.writeLineAt(12, fmt.Sprintf("confidence: %.0f%%", s.Confidence*100),
			fontReg, pdfSizeChrome, 0.55, 0.55, 0.55)
		d.gap(4)
	}
}

func (d *pdfDoc) renderCover(findings []core.Finding, diff *DiffCounts) {
	d.gap(24)
	d.writeLine("hyperz scan report", fontBold, pdfSizeH1, 0.10, 0.10, 0.10)
	d.writeLine("generated "+time.Now().UTC().Format(time.RFC3339), fontReg, pdfSizeBase, 0.45, 0.45, 0.45)
	d.gap(18)

	d.writeLine("Summary", fontBold, pdfSizeH2, 0.10, 0.10, 0.10)
	d.gap(4)
	d.hline(pdfBodyLeft, pdfBodyRight, d.y, 0.5, 0.85, 0.85, 0.85)
	d.gap(8)
	d.writeLine(fmt.Sprintf("Total findings: %d", len(findings)), fontReg, pdfSizeBase, 0, 0, 0)
	if diff != nil {
		d.writeLine(fmt.Sprintf("Diff vs baseline: %d new, %d persisting, %d resolved",
			diff.New, diff.Persisting, diff.Resolved),
			fontReg, pdfSizeBase, 0.30, 0.30, 0.30)
	}
	d.gap(10)

	if len(findings) == 0 {
		d.writeLine("No findings.", fontReg, pdfSizeBase, 0.45, 0.45, 0.45)
		return
	}

	bySev := map[core.Severity]int{}
	for _, f := range findings {
		bySev[f.Severity]++
	}

	const (
		swatchW = 14.0
		swatchH = 10.0
		rowH    = 18.0
	)
	for _, s := range severityOrder {
		n := bySev[s]
		if n == 0 {
			continue
		}
		d.ensureSpace(rowH)
		d.y -= rowH
		r, g, b := severityRGB(s)
		d.fillRect(pdfBodyLeft, d.y+2, swatchW, swatchH, r, g, b)
		d.text(pdfBodyLeft+swatchW+8, d.y+4, severityTitle(s), fontBold, pdfSizeBase, 0.15, 0.15, 0.15)
		d.text(pdfBodyLeft+swatchW+90, d.y+4, fmt.Sprintf("%d", n), fontReg, pdfSizeBase, 0.20, 0.20, 0.20)
	}
}

func (d *pdfDoc) renderSeverityHeading(sev core.Severity, n int) {
	d.gap(8)
	r, g, b := severityRGB(sev)
	barH := pdfSizeH2 * 1.2
	d.ensureSpace(barH + 10)
	d.y -= barH
	d.fillRect(pdfBodyLeft, d.y, 4, barH, r, g, b)
	d.text(pdfBodyLeft+14, d.y+5, fmt.Sprintf("%s findings (%d)", severityTitle(sev), n),
		fontBold, pdfSizeH2, 0.10, 0.10, 0.10)
	d.gap(8)
	d.hline(pdfBodyLeft, pdfBodyRight, d.y, 0.5, 0.85, 0.85, 0.85)
	d.gap(8)
}

// renderCheckGroup emits one block per (severity, check). Shared fields are
// pulled from the representative finding; per-URL variation is shown as an
// indented "affected" list. Only one sample evidence is rendered - the
// per-URL evidence overwhelmingly repeats the same response headers in a
// long scan, and reading 12 identical blocks gives no extra information.
func (d *pdfDoc) renderCheckGroup(g checkGroup) {
	rep := g.Rep
	n := len(g.All)
	r, gC, b := severityRGB(g.Severity)

	heading := fmt.Sprintf("[%s] %s", g.Severity, g.Check)
	if n > 1 {
		heading = fmt.Sprintf("%s (%d instances)", heading, n)
	} else if badge := diffStatusBadge(rep.DiffStatus); badge != "" {
		heading = fmt.Sprintf("(%s) %s", badge, heading)
	}
	d.writeLine(heading, fontBold, pdfSizeH3, r, gC, b)

	d.writeWrapped("title:  "+rep.Title, 0, fontReg, pdfSizeBase, 0, 0, 0)
	if refs := pdfJoinNonEmpty("  ", rep.CWE, rep.OWASP); refs != "" {
		d.writeWrapped("refs:   "+refs, 0, fontReg, pdfSizeBase, 0.25, 0.25, 0.25)
	}
	if rep.Detail != "" {
		d.writeWrapped("detail: "+rep.Detail, 0, fontReg, pdfSizeBase, 0.25, 0.25, 0.25)
	}
	if len(rep.Details) > 0 {
		if rep.Detail == "" {
			d.writeLine("details:", fontReg, pdfSizeBase, 0.25, 0.25, 0.25)
		}
		for _, item := range rep.Details {
			if item == "" {
				continue
			}
			d.writeWrapped("- "+item, 12, fontReg, pdfSizeBase, 0.25, 0.25, 0.25)
		}
	}
	if rep.Remediation != "" {
		d.writeWrapped("fix:    "+rep.Remediation, 0, fontReg, pdfSizeBase, 0.20, 0.35, 0.20)
	}

	if n == 1 {
		loc := rep.URL
		if loc == "" {
			loc = rep.Target
		}
		d.writeWrapped("url:    "+loc, 0, fontReg, pdfSizeBase, 0, 0, 0)
	} else {
		d.writeLine(fmt.Sprintf("affected URLs (%d):", n), fontReg, pdfSizeBase, 0, 0, 0)
		for _, f := range g.All {
			loc := f.URL
			if loc == "" {
				loc = f.Target
			}
			line := "- " + loc
			if badge := diffStatusBadge(f.DiffStatus); badge != "" {
				line = "- (" + badge + ") " + loc
			}
			// Per-instance title overrides (e.g. checks that encode the
			// vulnerable param into the title) are worth surfacing.
			if f.Title != rep.Title && f.Title != "" {
				line += " - " + f.Title
			}
			d.writeWrapped(line, 12, fontReg, pdfSizeBase, 0.20, 0.20, 0.20)
		}
	}

	if e := rep.Evidence; e != nil && (e.Method != "" || e.Status != 0 || e.Snippet != "" || e.Exchange != nil) {
		method := e.Method
		if method == "" {
			method = "GET"
		}
		reqURL := e.RequestURL
		if reqURL == "" {
			if rep.URL != "" {
				reqURL = rep.URL
			} else {
				reqURL = rep.Target
			}
		}
		label := "evidence:"
		if n > 1 {
			label = "sample evidence:"
		}
		d.writeWrapped(
			fmt.Sprintf("%s %s %s -> %d", label, method, reqURL, e.Status),
			0, fontReg, pdfSizeBase, 0.30, 0.30, 0.30)
		for _, line := range strings.Split(e.Snippet, "\n") {
			if line == "" {
				continue
			}
			d.writeWrapped(line, 12, fontReg, pdfSizeChrome, 0.35, 0.35, 0.35)
		}
		if ex := e.Exchange; ex != nil {
			d.renderExchangeBody("request body", ex.RequestBody, ex.RequestBodyTruncated)
			d.renderExchangeBody("response body", ex.ResponseBody, ex.ResponseBodyTruncated)
		}
	}
	if n == 1 && rep.DedupeKey != "" {
		d.writeLine("id: "+rep.DedupeKey, fontReg, pdfSizeChrome, 0.55, 0.55, 0.55)
	}
	d.gap(4)
}

func (d *pdfDoc) renderExchangeBody(label, body string, truncated bool) {
	if body == "" {
		return
	}
	heading := label
	if truncated {
		heading += " (truncated)"
	}
	d.writeWrapped(heading+":", 0, fontBold, pdfSizeChrome, 0.30, 0.30, 0.30)
	for _, line := range strings.Split(body, "\n") {
		d.writeWrapped(line, 12, fontReg, pdfSizeChrome, 0.35, 0.35, 0.35)
	}
}

func pdfJoinNonEmpty(sep string, parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func (d *pdfDoc) separator() {
	d.gap(2)
	d.ensureSpace(6)
	d.hline(pdfBodyLeft, pdfBodyRight, d.y, 0.4, 0.90, 0.90, 0.90)
	d.gap(8)
}

func severityRGB(s core.Severity) (float64, float64, float64) {
	switch s {
	case core.SeverityCritical:
		return 0.55, 0.05, 0.10
	case core.SeverityHigh:
		return 0.80, 0.20, 0.15
	case core.SeverityMedium:
		return 0.85, 0.55, 0.10
	case core.SeverityLow:
		return 0.20, 0.45, 0.80
	default:
		return 0.45, 0.45, 0.45
	}
}

func severityTitle(s core.Severity) string {
	str := string(s)
	if str == "" {
		return ""
	}
	return strings.ToUpper(str[:1]) + str[1:]
}

// approxWidth estimates rendered width for Helvetica at the given size. Good
// enough for centering/right-aligning short chrome strings without per-glyph
// metrics.
func approxWidth(s string, size float64) float64 {
	return float64(len(s)) * size * 0.52
}

// serialize lays out the PDF as: catalog, pages tree, two fonts, then
// alternating (page, contents) objects - one pair per logical page. Object
// IDs are assigned in order of writing so the page tree can reference them
// by formula (page i lives at object 5+2i, its content stream at 6+2i).
func (d *pdfDoc) serialize(w io.Writer) error {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xFF\xFF\xFF\xFF\n")

	var offsets []int
	addObj := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	addStream := func(stream []byte) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n<< /Length %d >>\nstream\n", len(offsets), len(stream))
		out.Write(stream)
		out.WriteString("\nendstream\nendobj\n")
	}

	addObj("<< /Type /Catalog /Pages 2 0 R >>")

	var kids strings.Builder
	for i := range d.pages {
		fmt.Fprintf(&kids, "%d 0 R ", 5+2*i)
	}
	addObj(fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>",
		len(d.pages), strings.TrimSpace(kids.String())))

	addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")

	for i, content := range d.pages {
		contentID := 5 + 2*i + 1
		addObj(fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>",
			pdfPageW, pdfPageH, contentID))
		addStream(content.Bytes())
	}

	xrefOffset := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(offsets)+1, xrefOffset)

	_, err := w.Write(out.Bytes())
	return err
}

// pdfEscape makes s safe inside a PDF literal string `( ... )`. Backslash
// and parens are escaped; non-printable / non-ASCII bytes are replaced with
// '?' so we don't have to ship a CMap or worry about WinAnsi byte mappings.
func pdfEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '(' || c == ')' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7E:
			b.WriteByte('?')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// pdfWrap performs word-aware wrapping with hard-splits for words longer than
// max. Width is approximated in characters because we don't carry per-glyph
// metrics; for Helvetica 10pt this lands within the right margin in practice.
func pdfWrap(s string, max int) []string {
	if max <= 0 || len(s) <= max {
		return []string{s}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{s}
	}
	var lines []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			lines = append(lines, cur.String())
			cur.Reset()
		}
	}
	for _, w := range words {
		for len(w) > max {
			flush()
			lines = append(lines, w[:max])
			w = w[max:]
		}
		switch {
		case cur.Len() == 0:
			cur.WriteString(w)
		case cur.Len()+1+len(w) > max:
			flush()
			cur.WriteString(w)
		default:
			cur.WriteByte(' ')
			cur.WriteString(w)
		}
	}
	flush()
	return lines
}
