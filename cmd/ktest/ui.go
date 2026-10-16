package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// term renders ktest's output. On an interactive terminal it uses color,
// box-drawing glyphs and a progress line that redraws in place; anywhere else
// (a pipe, CI, a test, NO_COLOR, TERM=dumb) it degrades to plain ASCII lines
// with no escape sequences, so logs and smoke tests stay readable.
type term struct {
	w       io.Writer
	color   bool
	unicode bool
	live    bool // may redraw the current line
	mu      sync.Mutex
}

type tone int

const (
	toneInfo tone = iota
	toneOK
	toneWarn
	toneFail
)

func newTerm(w io.Writer) *term {
	t := &term{w: w}
	f, ok := w.(*os.File)
	if !ok || !enableVT(f) {
		return t
	}
	t.live, t.color, t.unicode = true, true, true
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		t.color = false
	}
	if os.Getenv("KTEST_ASCII") != "" {
		t.unicode = false
	}
	return t
}

// plainTerm is for tests and any caller that wants no decoration.
func plainTerm(w io.Writer) *term { return &term{w: w} }

var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

func visibleLen(s string) int { return utf8.RuneCountInString(ansiPattern.ReplaceAllString(s, "")) }

func (t *term) paint(code, s string) string {
	if !t.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (t *term) Bold(s string) string   { return t.paint("1", s) }
func (t *term) Dim(s string) string    { return t.paint("90", s) }
func (t *term) Green(s string) string  { return t.paint("32", s) }
func (t *term) Red(s string) string    { return t.paint("31", s) }
func (t *term) Yellow(s string) string { return t.paint("33", s) }
func (t *term) Cyan(s string) string   { return t.paint("36", s) }

func (t *term) tinted(k tone, s string) string {
	switch k {
	case toneOK:
		return t.Green(s)
	case toneWarn:
		return t.Yellow(s)
	case toneFail:
		return t.Red(s)
	}
	return t.Cyan(s)
}

func (t *term) glyph(k tone) string {
	if t.unicode {
		return [...]string{"•", "✓", "!", "✗"}[k]
	}
	return [...]string{"-", "+", "!", "x"}[k]
}

func (t *term) rule(n int) string {
	if t.unicode {
		return strings.Repeat("─", n)
	}
	return strings.Repeat("-", n)
}

// Printf writes raw text.
func (t *term) Printf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	text := fmt.Sprintf(format, args...)
	if !t.unicode {
		text = asciiFallback.Replace(text)
	}
	_, _ = io.WriteString(t.w, text)
}

// asciiFallback replaces the few non-ASCII symbols used in messages when the
// output is not an interactive terminal.
var asciiFallback = strings.NewReplacer("→", "->", "←", "<-", "…", "...", "·", "-")

// Println writes a line.
func (t *term) Println(s string) { t.Printf("%s\n", s) }

// Heading prints the program banner for a view.
func (t *term) Heading(title, subtitle string) {
	line := t.Bold(t.Cyan("ktest")) + t.Dim("  ·  ") + t.Bold(title)
	if !t.unicode {
		line = "ktest - " + title
	}
	t.Printf("\n%s\n", line)
	if subtitle != "" {
		t.Printf("%s\n", t.Dim(subtitle))
	}
	t.Printf("%s\n", t.Dim(t.rule(max(visibleLen(title)+10, 44))))
}

// Line prints a status line with a colored glyph.
func (t *term) Line(k tone, format string, args ...any) {
	t.Printf("  %s %s\n", t.tinted(k, t.glyph(k)), fmt.Sprintf(format, args...))
}

// Note prints a dimmed continuation line under a status line.
func (t *term) Note(format string, args ...any) {
	t.Printf("    %s\n", t.Dim(fmt.Sprintf(format, args...)))
}

// Bar renders a fixed-width bar for a fraction in [0,1].
func (t *term) Bar(frac float64, width int, k tone) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	filled := int(frac*float64(width) + 0.5)
	on, off := "#", "."
	if t.unicode {
		on, off = "▰", "▱"
	}
	return t.tinted(k, strings.Repeat(on, filled)) + t.Dim(strings.Repeat(off, width-filled))
}

// Box prints a bordered panel.
func (t *term) Box(title string, k tone, lines []string) {
	inner := visibleLen(title) + 2
	for _, l := range lines {
		inner = max(inner, visibleLen(l))
	}
	tl, tr, bl, br, h, v := "+", "+", "+", "+", "-", "|"
	if t.unicode {
		tl, tr, bl, br, h, v = "╭", "╮", "╰", "╯", "─", "│"
	}
	edge := func(s string) string { return t.tinted(k, s) }
	t.mu.Lock()
	defer t.mu.Unlock()
	head := " " + title + " "
	fmt.Fprintf(t.w, "%s%s%s%s\n", edge(tl+h), t.Bold(t.tinted(k, head)), edge(strings.Repeat(h, max(inner+2-visibleLen(head)-1, 0))+tr), "")
	for _, l := range lines {
		fmt.Fprintf(t.w, "%s %s%s %s\n", edge(v), l, strings.Repeat(" ", inner-visibleLen(l)), edge(v))
	}
	fmt.Fprintf(t.w, "%s\n", edge(bl+strings.Repeat(h, inner+2)+br))
}

// progress is one phase with a known number of units.
type progress struct {
	t       *term
	label   string
	total   int
	start   time.Time
	lastPct int
	drawn   bool
}

func (t *term) Progress(label string, total int) *progress {
	p := &progress{t: t, label: label, total: max(total, 1), start: time.Now(), lastPct: -1}
	p.Set(0, "")
	return p
}

// Set redraws the line in place on a terminal; elsewhere it prints at most
// every 25 percent so logs stay short.
func (p *progress) Set(done int, detail string) {
	frac := float64(done) / float64(p.total)
	pct := int(frac*100 + 0.5)
	t := p.t
	if !t.live {
		if pct/25 == p.lastPct/25 && pct != 100 && p.lastPct >= 0 {
			return
		}
		p.lastPct = pct
		t.Printf("  .. %-34s %3d%%  %s\n", p.label, pct, detail)
		return
	}
	p.lastPct = pct
	p.drawn = true
	t.Printf("\r\x1b[2K  %s %-30s %s %3d%%  %s", t.Cyan(t.glyph(toneInfo)), p.label, t.Bar(frac, 20, toneInfo), pct, t.Dim(detail))
}

// Finish replaces the progress line by its final state.
func (p *progress) Finish(k tone, summary string) {
	t := p.t
	if t.live && p.drawn {
		t.Printf("\r\x1b[2K")
	}
	t.Printf("  %s %-30s %s  %s\n", t.tinted(k, t.glyph(k)), p.label, t.Dim(shortDur(time.Since(p.start))), summary)
}

func shortDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
