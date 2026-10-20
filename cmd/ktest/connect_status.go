package main

import (
	"fmt"
	"io"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// connectionStatus is the one answer to "am I connected?": a small panel
// pinned under the live log and redrawn every second, mirrored in the window
// title. It is computed from live proxy state, never from the startup verdict,
// so it changes the moment an exit verifies or disappears.
type connectionStatus struct {
	t       *term
	mode    ConnectionMode
	proxy   *smartproxy.Proxy
	exit    func() string // managed exit status; may be nil
	socks   string
	http    string
	stop    string
	tunWant bool
	tunOn   func() bool
	feed    *siteEvents
	started time.Time
	since   time.Time // when the current state began
	last    string    // state key last announced
}

type statusView struct {
	key   string // state identity; a change is announced in the log
	tone  tone
	title string
	lines []string
}

// Searching longer than this without a verified exit is shown as a failure,
// so a stalled search never looks like a slow success.
const notConnectedAfter = 3 * time.Minute

func (s *connectionStatus) view(now time.Time) statusView {
	t := s.t
	total, verified := s.proxy.ExitCounts()
	exitText := ""
	if s.exit != nil {
		exitText = s.exit()
	}
	tunOn := s.tunOn != nil && s.tunOn()
	var v statusView
	var status, exitLine string
	switch {
	case s.mode.exitOnly() && verified > 0:
		v.key, v.tone, v.title = "connected", toneOK, "CONNECTED"
		status = t.Green("Connected through a verified foreign exit") + " · " + plainDuration(now.Sub(s.since))
	case s.mode.exitOnly() && now.Sub(s.started) >= notConnectedAfter:
		v.key, v.tone, v.title = "failing", toneFail, "NOT CONNECTED"
		status = t.Red("No working exit yet") + " · still searching for " + plainDuration(now.Sub(s.started)) + "; traffic is blocked"
	case s.mode.exitOnly():
		v.key, v.tone, v.title = "connecting", toneWarn, "CONNECTING"
		step := "searching for a foreign exit"
		if total > 0 {
			step = "verifying an exit that came up"
		}
		status = t.Yellow(step) + " · " + plainDuration(now.Sub(s.started)) + "; traffic is blocked until it verifies"
	default:
		v.key, v.tone, v.title = "connected", toneOK, "CONNECTED"
		status = t.Green("Connected through local anti-DPI routes") + " · " + plainDuration(now.Sub(s.since))
		switch {
		case verified > 0:
			exitLine = t.Green("ready")
		case total > 0:
			exitLine = t.Yellow("verifying")
		default:
			exitLine = "not ready"
		}
		exitLine = "Foreign exit for AI/TikTok: " + exitLine
	}
	if t.unicode {
		v.title = map[tone]string{toneOK: "● ", toneWarn: "◌ ", toneFail: "✕ "}[v.tone] + v.title
	}
	v.lines = append(v.lines, "Status   "+status)
	switch {
	case tunOn:
		v.lines = append(v.lines, "Use      "+t.Green("Whole PC")+" (TUN on) · TCP apps need no setup")
	case s.tunWant && v.key != "connected":
		v.lines = append(v.lines, "Use      Whole PC (TUN) starts automatically once connected")
	default:
		use := "Set apps to SOCKS5 " + s.socks
		if s.http != "" {
			use += " or HTTP " + s.http
		}
		v.lines = append(v.lines, "Use      "+use)
	}
	if exitLine != "" {
		v.lines = append(v.lines, "Exit     "+exitLine)
	}
	if exitText != "" {
		v.lines = append(v.lines, "         "+t.Dim(exitText))
	}
	if s.feed != nil {
		if ok, fail := s.feed.ok.Load(), s.feed.fail.Load(); ok+fail > 0 {
			v.lines = append(v.lines, fmt.Sprintf("Traffic  %d connections opened · %d without a working route", ok, fail))
		}
	}
	v.lines = append(v.lines, "Stop     "+s.stop)
	return v
}

// render redraws the panel; a state change is also written to the log and
// the window title, so it stays visible in scrollback and from the taskbar.
func (s *connectionStatus) render(now time.Time) {
	v := s.view(now)
	changed := v.key != s.last
	if changed && s.last != "" {
		s.since = now // durations restart when the state changes
		v = s.view(now)
		s.t.Line(v.tone, "%s", map[string]string{
			"connected":  "Connected",
			"connecting": "Connection lost; searching for another exit",
			"failing":    "Still not connected; the search continues",
		}[v.key])
	}
	if changed {
		s.last = v.key
		s.t.SetTitle("ktest · " + map[string]string{"connected": "connected", "connecting": "connecting…", "failing": "NOT connected"}[v.key])
	}
	if s.t.PinBox(v.title, v.tone, v.lines) {
		return
	}
	if changed {
		// Without an in-place panel, print the box once per state change.
		s.t.Box(v.title, v.tone, v.lines)
	}
}

func (s *connectionStatus) close() {
	s.t.ClearPinnedBox()
	s.t.SetTitle("ktest")
}

func plainDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// SetTitle sets the terminal window title on interactive terminals only.
func (t *term) SetTitle(title string) {
	if !t.live {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, _ = io.WriteString(t.w, "\x1b]0;"+cleanTerminalText(title, false)+"\x07")
}
