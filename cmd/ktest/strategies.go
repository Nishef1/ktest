package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Nishef1/ktest/internal/dnscheck"
)

// defaultStrategies is written next to the profiles by `ktest strategies -write`
// and used when that editable file does not exist.
//
//go:embed byedpi-strategies.txt
var defaultStrategies string

// strategiesFile is the editable ByeDPI strategy list inside the portable folder.
func strategiesFile(base string) string {
	return filepath.Join(base, "profiles", "byedpi-strategies.txt")
}

// byeDPIStrategy is one candidate command line for ciadpi (without the listen
// address, which ktest always supplies).
type byeDPIStrategy struct {
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
func parseStrategies(r io.Reader) ([]byeDPIStrategy, error) {
	var out []byeDPIStrategy
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
		out = append(out, byeDPIStrategy{Label: label, Args: args})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no strategies found")
	}
	return out, nil
}

// loadStrategies uses the editable file when present, else the built-in list.
func loadStrategies(base string) (list []byeDPIStrategy, source string, err error) {
	path := strategiesFile(base)
	f, openErr := os.Open(path)
	if openErr == nil {
		defer f.Close()
		list, err = parseStrategies(f)
		if err != nil {
			err = fmt.Errorf("%s: %w", path, err)
		}
		return list, path, err
	}
	if !errors.Is(openErr, os.ErrNotExist) {
		return nil, path, openErr
	}
	list, err = parseStrategies(strings.NewReader(defaultStrategies))
	return list, "built-in list", err
}

// method is one launchable way to get a local proxy.
type method struct {
	label  string
	port   int
	launch launcher
	err    error // set when the method cannot even be prepared
}

func byeDPIBinary(base string) string {
	bin := filepath.Join(base, "cores", "ciadpi")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	return bin
}

// byeDPILauncher runs ciadpi on the given local port until ctx ends.
func byeDPILauncher(bin string, port int, strategy []string, output io.Writer) launcher {
	args := append([]string{"-i", "127.0.0.1", "-p", fmt.Sprint(port)}, strategy...)
	return func(ctx context.Context, _ *dnscheck.Result) error {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdout, cmd.Stderr = output, output
		err := cmd.Run()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ByeDPI exited: %w", err)
		}
		return errors.New("ByeDPI exited unexpectedly")
	}
}

// expandMethod turns an `auto -methods` token into launchable methods:
// 1-4 are the menu entries, "s" is every strategy in the editable list.
func expandMethod(token, base string, output io.Writer) []method {
	if token != "s" {
		launch, port, label, err := terminalMode(token, base, output)
		if err != nil {
			if label == "" {
				label = "method " + token
			}
			return []method{{label: label, err: err}}
		}
		return []method{{label: label, port: port, launch: launch}}
	}
	bin := byeDPIBinary(base)
	if info, err := os.Stat(bin); err != nil || info.IsDir() {
		return []method{{label: "ByeDPI strategies", err: fmt.Errorf("missing %s; download the complete portable ZIP", bin)}}
	}
	list, _, err := loadStrategies(base)
	if err != nil {
		return []method{{label: "ByeDPI strategies", err: err}}
	}
	out := make([]method, 0, len(list))
	for _, s := range list {
		out = append(out, method{label: "ByeDPI: " + s.Label, port: byeDPIPort, launch: byeDPILauncher(bin, byeDPIPort, s.Args, output)})
	}
	return out
}

// runStrategies lists the effective ByeDPI strategies, or writes the editable
// file once so users can add their own.
func runStrategies(args []string) int {
	fs := flag.NewFlagSet("strategies", flag.ContinueOnError)
	exe, _ := os.Executable()
	base := fs.String("base", filepath.Dir(exe), "portable folder holding cores/ and profiles/")
	write := fs.Bool("write", false, "create profiles/byedpi-strategies.txt from the built-in list if it does not exist")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest strategies [-write] [-base DIR]")
		return 2
	}
	path := strategiesFile(*base)
	if *write {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		switch {
		case errors.Is(err, os.ErrExist):
			fmt.Println("Already exists, not overwritten:", path)
		case err != nil:
			fmt.Fprintln(os.Stderr, err)
			return 1
		default:
			_, werr := f.WriteString(defaultStrategies)
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				fmt.Fprintln(os.Stderr, werr)
				return 1
			}
			fmt.Println("Wrote", path)
		}
	}
	list, source, err := loadStrategies(*base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strategies:", err)
		return 1
	}
	fmt.Printf("%d ByeDPI strategies from %s:\n", len(list), source)
	for i, s := range list {
		fmt.Printf("%2d. %-34s %s\n", i+1, s.Label, strings.Join(s.Args, " "))
	}
	return 0
}
