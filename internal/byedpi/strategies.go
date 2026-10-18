// Package byedpi shares the original ciadpi strategy catalog between CLI and Android.
package byedpi

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

//go:embed strategies.txt
var DefaultStrategies string

// Strategy is one candidate command line for ciadpi (without the listen
// address, which ktest always supplies).
type Strategy struct {
	Label string
	Args  []string
}

// Only the real upstream v0.17.3 long option names are accepted. GNU getopt
// accepts abbreviated long options, which could otherwise disguise --ip,
// --port or --connect-to and escape the local, IP-preserving SOCKS boundary.
var strategyLongOptions = map[string]bool{
	"--no-domain": true, "--no-ipv6": true, "--no-udp": true,
	"--max-conn": true, "--buf-size": true, "--debug": true, "--tfo": true,
	"--auto": true, "--auto-mode": true, "--cache-ttl": true,
	"--timeout": true, "--copy": true, "--cache-file": true,
	"--proto": true, "--hosts": true, "--ipset": true, "--pf": true,
	"--round": true, "--split": true, "--disorder": true, "--oob": true,
	"--disoob": true, "--fake": true, "--md5sig": true,
	"--fake-sni": true, "--ttl": true, "--fake-data": true,
	"--fake-offset": true, "--fake-tls-mod": true, "--oob-data": true,
	"--mod-http": true, "--tlsrec": true, "--tlsminor": true,
	"--udp-fake": true, "--def-ttl": true, "--drop-sack": true,
	"--wait-send": true, "--await-int": true, "--cache-merge": true,
	"--comment": true,
}

// These long flags have no operand; every other supported long flag does.
// Track option/value pairs so a quoted fake payload containing "--ip=..."
// is data, not mistaken for a listener override.
var strategyLongNoValue = map[string]bool{
	"--no-domain": true, "--no-ipv6": true, "--no-udp": true,
	"--tfo": true, "--md5sig": true, "--drop-sack": true,
	"--wait-send": true,
}

// The caller owns the listener address and process lifetime. Additionally,
// connect-to/transparent/protect-path may change the forwarding or trust
// boundary, so these are forbidden in an IP-preserving local bypass route.
var reservedLongOptions = []string{
	"--ip", "--port", "--daemon", "--pidfile", "--connect-to",
	"--transparent", "--protect-path", "--conn-ip",
}

// Upstream getopt treats adjacent short flags as a group (for example -Ui...).
// Scan option-only prefixes but stop when a flag consumes the remaining text.
func reservedStrategyOption(arg string) bool {
	if arg == "--" {
		return true
	}
	if strings.HasPrefix(arg, "--") {
		name, _, _ := strings.Cut(arg, "=")
		for _, reserved := range reservedLongOptions {
			if strings.HasPrefix(reserved, name) {
				return true
			}
		}
		return !strategyLongOptions[name]
	}
	if !strings.HasPrefix(arg, "-") || len(arg) == 1 {
		return false
	}
	for i := 1; i < len(arg); i++ {
		switch arg[i] {
		case 'i', 'p', 'D', 'w', 'C', 'E', 'P', 'I':
			return true
		case 'N', 'X', 'U', 'F', 'S', 'Y', 'Z':
			// Option without argument: another short option may follow.
			continue
		default:
			// An option with an argument consumes its remaining characters.
			return false
		}
	}
	return false
}

// splitStrategyArgs preserves quoted values (including spaces) as single
// argv elements. Unlike a shell it never expands variables, globs or command
// substitutions. Backslashes before ordinary characters remain unchanged,
// which also preserves Windows-style paths and ByeDPI escape sequences.
func splitStrategyArgs(input string) ([]string, error) {
	runes := []rune(input)
	var args []string
	var word strings.Builder
	var quote rune
	started := false
	flush := func() error {
		if !started {
			return nil
		}
		if word.Len() == 0 {
			return errors.New("empty strategy argument")
		}
		args = append(args, word.String())
		word.Reset()
		started = false
		return nil
	}
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == '\\' && i+1 < len(runes) {
			next := runes[i+1]
			if next == '\\' || next == '"' || next == '\'' || unicode.IsSpace(next) {
				word.WriteRune(next)
				started = true
				i++
				continue
			}
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			started = true
			continue
		}
		switch {
		case c == '"' || c == '\'':
			quote = c
			started = true
		case unicode.IsSpace(c):
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			word.WriteRune(c)
			started = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quoted argument")
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return args, nil
}

// ParseStrategies reads "label | arguments" lines. Blank lines and lines
// starting with # are ignored. A line without "|" uses its arguments as label.
func ParseStrategies(r io.Reader) ([]Strategy, error) {
	var out []Strategy
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, argText := line, line
		if i := strings.Index(line, "|"); i >= 0 {
			label, argText = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		}
		args, err := splitStrategyArgs(argText)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if len(args) == 0 {
			return nil, fmt.Errorf("line %d: no arguments", n)
		}
		for i := 0; i < len(args); i++ {
			a := args[i]
			if reservedStrategyOption(a) {
				return nil, fmt.Errorf("line %d: %q cannot be used in a local ByeDPI strategy", n, a)
			}
			needsValue := false
			switch {
			case strings.HasPrefix(a, "--"):
				flag, _, inline := strings.Cut(a, "=")
				needsValue = !inline && !strategyLongNoValue[flag]
			case strings.HasPrefix(a, "-") && len(a) == 2:
				// Long option operands and one-character short option
				// operands are separate argv tokens, not new options.
				needsValue = !strings.ContainsRune("NXUFSYZ", rune(a[1]))
			}
			if needsValue {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("line %d: %s requires a value", n, a)
				}
				i++
			}
		}
		key := strings.Join(args, "\x00")
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
