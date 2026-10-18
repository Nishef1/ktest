// Package byedpi shares the original ciadpi strategy catalog between CLI and Android.
package byedpi

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
)

//go:embed strategies.txt
var DefaultStrategies string

// Strategy is one candidate command line for ciadpi (without the listen
// address, which ktest always supplies).
type Strategy struct {
	Label string
	Args  []string
}

// forbiddenStrategyFlags would move or detach the listener, which ktest has to
// control to verify the right proxy and to stop it cleanly.
var forbiddenStrategyFlags = map[string]bool{
	"-i": true, "--ip": true, "-p": true, "--port": true,
	"-D": true, "--daemon": true, "-w": true, "--pidfile": true,
}

// parseStrategies reads "label | arguments" lines. Blank lines and lines
// starting with # are ignored. A line without "|" uses its arguments as label.
func ParseStrategies(r io.Reader) ([]Strategy, error) {
	var out []Strategy
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, argText := line, line
		if i := strings.Index(line, "|"); i >= 0 {
			label, argText = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		}
		args := strings.Fields(argText)
		if len(args) == 0 {
			return nil, fmt.Errorf("line %d: no arguments", n)
		}
		for _, a := range args {
			name := a
			if i := strings.Index(a, "="); i > 0 {
				name = a[:i]
			}
			if forbiddenStrategyFlags[name] {
				return nil, fmt.Errorf("line %d: %s is set by ktest and not allowed in a strategy", n, name)
			}
		}
		key := strings.Join(args, " ")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Strategy{Label: label, Args: args})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no strategies found")
	}
	return out, nil
}
