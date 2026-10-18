package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/dnscheck"
)

// Keep the editable CLI file and Android on the same built-in catalog.
var defaultStrategies = byedpi.DefaultStrategies

// strategiesFile is the editable ByeDPI strategy list inside the portable folder.
func strategiesFile(base string) string {
	return filepath.Join(base, "profiles", "byedpi-strategies.txt")
}

type byeDPIStrategy = byedpi.Strategy

func parseStrategies(r io.Reader) ([]byeDPIStrategy, error) {
	return byedpi.ParseStrategies(r)
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
		configureEnrollmentProcess(cmd)
		cmd.Stdout, cmd.Stderr = output, output
		err := runTracked(cmd)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ByeDPI exited: %w", err)
		}
		return errors.New("ByeDPI exited unexpectedly")
	}
}

// runStrategies lists the effective ByeDPI strategies, or writes the editable
// file once so users can add their own.
func runStrategies(args []string) int {
	fs := flag.NewFlagSet("strategies", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "portable folder holding cores/ and profiles/")
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
