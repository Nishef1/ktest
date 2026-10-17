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

	xterm "golang.org/x/term"
)

// term renders ktest's output. On an interactive terminal it uses color,
// box-drawing glyphs and a progress line that redraws in place; anywhere else
// (a pipe, CI, a test, NO_COLOR, TERM=dumb) it degrades to plain ASCII lines
// with no escape sequences, so logs and smoke tests stay readable.
type term struct {
	w            io.Writer
	color        bool
	unicode      bool
	live         bool // may redraw the current line
	columns      int  // explicit width for captured renders; zero uses the terminal
	file         *os.File
	progressLine string
	mu           sync.Mutex
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
	if !ok || !xterm.IsTerminal(int(f.Fd())) {
		return t
	}
	t.file = f
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return t
	}
	if !enableVT(f) {
		return t
	}
	t.live, t.color, t.unicode = true, true, true
	if os.Getenv("KTEST_ASCII") != "" {
		t.unicode = false
	}
	return t
}

// plainTerm is for tests and any caller that wants no decoration.
func plainTerm(w io.Writer) *term { return &term{w: w} }

var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

func visibleLen(s string) int { return utf8.RuneCountInString(ansiPattern.ReplaceAllString(s, "")) }

func (t *term) width() int {
	if t.columns > 0 {
		return t.columns
	}
	if t.file != nil {
		if w, _, err := xterm.GetSize(int(t.file.Fd())); err == nil && w > 0 {
			return w
		}
	}
	return 80
}

// wrapText preserves SGR colors and explicit newlines, including when an
// unbroken hostname, URL or path is wider than the terminal.
func wrapText(s string, width int) []string {
	width = max(width, 1)
	var lines []string
	for _, paragraph := range strings.Split(s, "\n") {
		if visibleLen(paragraph) <= width {
			lines = append(lines, paragraph)
			continue
		}
		line := ""
		for _, word := range strings.Fields(paragraph) {
			if line != "" && visibleLen(line)+1+visibleLen(word) > width {
				lines = append(lines, line)
				line = ""
			}
			for visibleLen(word) > width {
				head, rest := splitVisible(word, width)
				lines = append(lines, head)
				word = rest
			}
			if line != "" {
				line += " "
			}
			line += word
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	style := ""
	for i, line := range lines {
		prefix := style
		for _, code := range ansiPattern.FindAllString(line, -1) {
			if code == "\x1b[0m" || code == "\x1b[m" {
				style = ""
			} else {
				style += code
			}
		}
		lines[i] = prefix + line
		if style != "" {
			lines[i] += "\x1b[0m"
		}
	}
	return lines
}

func splitVisible(s string, width int) (string, string) {
	i, cells := 0, 0
	for i < len(s) {
		if loc := ansiPattern.FindStringIndex(s[i:]); loc != nil && loc[0] == 0 {
			i += loc[1]
			continue
		}
		if cells == width {
			break
		}
		_, n := utf8.DecodeRuneInString(s[i:])
		i += n
		cells++
	}
	return s[:i], s[i:]
}

// text keeps wrapped continuations aligned and emits a whole message atomically.
func (t *term) text(prefix, continuation, message string) {
	if !t.unicode {
		message = asciiFallback.Replace(message)
	}
	lines := wrapText(message, max(t.width()-visibleLen(prefix)-1, 1))
	var out strings.Builder
	for i, line := range lines {
		if i > 0 {
			out.WriteString(continuation)
		} else {
			out.WriteString(prefix)
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	t.Printf("%s", out.String())
}

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

// Printf writes text, fitting long rows and prompts to the current terminal.
func (t *term) Printf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	text := fmt.Sprintf(format, args...)
	if !t.unicode {
		text = asciiFallback.Replace(text)
	}
	rows := strings.Split(text, "\n")
	for i, row := range rows {
		if visibleLen(row) < t.width() {
			continue
		}
		indent := len(row) - len(strings.TrimLeft(row, " "))
		indent = min(indent, max(t.width()/3, 1))
		padding := strings.Repeat(" ", indent)
		wrapped := wrapText(strings.TrimLeft(row, " "), max(t.width()-indent-1, 1))
		rows[i] = padding + strings.Join(wrapped, "\n"+padding)
	}
	text = strings.Join(rows, "\n")
	if t.progressLine != "" {
		_, _ = io.WriteString(t.w, "\r\x1b[2K")
	}
	_, _ = io.WriteString(t.w, text)
	if t.progressLine != "" && strings.HasSuffix(text, "\n") {
		_, _ = io.WriteString(t.w, t.progressLine)
	}
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
	t.Printf("\n")
	t.text("", "", line)
	if subtitle != "" {
		t.text("", "", t.Dim(subtitle))
	}
	t.Printf("%s\n", t.Dim(t.rule(min(max(visibleLen(title)+10, 44), t.width()-1))))
}

// Line prints a status line with a colored glyph.
func (t *term) Line(k tone, format string, args ...any) {
	t.text("  "+t.tinted(k, t.glyph(k))+" ", "    ", fmt.Sprintf(format, args...))
}

// Note prints a dimmed continuation line under a status line.
func (t *term) Note(format string, args ...any) {
	t.text("    ", "    ", t.Dim(fmt.Sprintf(format, args...)))
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
	if !t.unicode {
		title = asciiFallback.Replace(title)
	}
	inner := visibleLen(title) + 2
	for _, l := range lines {
		inner = max(inner, visibleLen(l))
	}
	inner = min(inner, max(t.width()-5, 1))
	var wrapped []string
	for _, line := range lines {
		if !t.unicode {
			line = asciiFallback.Replace(line)
		}
		wrapped = append(wrapped, wrapText(line, inner)...)
	}
	tl, tr, bl, br, h, v := "+", "+", "+", "+", "-", "|"
	if t.unicode {
		tl, tr, bl, br, h, v = "╭", "╮", "╰", "╯", "─", "│"
	}
	edge := func(s string) string { return t.tinted(k, s) }
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.progressLine != "" {
		_, _ = io.WriteString(t.w, "\r\x1b[2K")
		t.progressLine = ""
	}
	head := " " + title + " "
	if visibleLen(head)+1 > inner+2 {
		fmt.Fprintf(t.w, "%s\n", edge(tl+strings.Repeat(h, inner+2)+tr))
		wrapped = append(wrapText(t.Bold(t.tinted(k, title)), inner), wrapped...)
	} else {
		fmt.Fprintf(t.w, "%s%s%s\n", edge(tl+h), t.Bold(t.tinted(k, head)), edge(strings.Repeat(h, inner+2-visibleLen(head)-1)+tr))
	}
	for _, l := range wrapped {
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
	frac := min(max(float64(done)/float64(p.total), 0), 1)
	pct := int(frac*100 + 0.5)
	t := p.t
	if !t.live {
		if pct/25 == p.lastPct/25 && pct != 100 && p.lastPct >= 0 {
			return
		}
		p.lastPct = pct
		t.text("  .. ", "     ", fmt.Sprintf("%s  %3d%%  %s", p.label, pct, detail))
		return
	}
	p.lastPct = pct
	p.drawn = true
	label := fmt.Sprintf("%s  %3d%%", p.label, pct)
	if t.width() >= 80 {
		label = fmt.Sprintf("%s %s", label, t.Bar(frac, 12, toneInfo))
	}
	if detail != "" {
		label += "  " + t.Dim(detail)
	}
	line, _ := splitVisible("  "+t.Cyan(t.glyph(toneInfo))+" "+label, max(t.width()-1, 1))
	if t.color {
		line += "\x1b[0m"
	}
	t.mu.Lock()
	t.progressLine = line
	fmt.Fprintf(t.w, "\r\x1b[2K%s", line)
	t.mu.Unlock()
}

// Finish replaces the progress line by its final state.
func (p *progress) Finish(k tone, summary string) {
	t := p.t
	if t.live && p.drawn {
		t.mu.Lock()
		t.progressLine = ""
		_, _ = io.WriteString(t.w, "\r\x1b[2K")
		t.mu.Unlock()
	}
	t.Line(k, "%s  %s  %s", p.label, t.Dim(shortDur(time.Since(p.start))), summary)
}

func shortDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
