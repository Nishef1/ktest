package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/tlsshape"
)

// tlsShape is F&F and the MASQUE server name for one session: the user's
// choices and, for what was left to auto, this network's calibration.
type tlsShape struct {
	opts   tlsshape.Options
	result *tlsshape.Result
}

func tlsCalibrationFile() string {
	if warpDir() == "" {
		return ""
	}
	return filepath.Join(warpDir(), "tls-calibration.json")
}

func aetherTLSOptions(o connectOptions) (tlsshape.Options, error) {
	return tlsshape.ParseOptions(o.aetherFingerprint, o.masqueSNI, o.aetherFragment)
}

// tlsCalibrationBudget bounds the measurement before the first connection on
// a network; a network that answers takes a few seconds.
const tlsCalibrationBudget = 15 * time.Second

// sessionTLSShape returns the shape for a connection, calibrating this network
// when its saved calibration is missing or stale. Psiphon and Tor sessions
// have no MASQUE handshake to shape.
func sessionTLSShape(ctx context.Context, o connectOptions, network string, u *term) tlsShape {
	opts, err := aetherTLSOptions(o)
	if err != nil {
		return tlsShape{opts: tlsshape.Options{Fingerprint: tlsshape.Auto, SNI: tlsshape.Auto, Fragment: tlsshape.Auto}}
	}
	s := tlsShape{opts: opts}
	if o.mode == ModePsiphon || o.mode == ModeTor || o.mode == ModeWindscribe ||
		strings.HasPrefix(o.aetherMethod, "psiphon") || o.aetherMethod == "tor" {
		return s
	}
	if r, ok := tlsshape.Cached(tlsCalibrationFile(), network, opts); ok {
		s.result = &r
		return s
	}
	u.Line(toneInfo, "Measuring the MASQUE hello on this network (F&F, SNI; up to %s, then saved)", tlsCalibrationBudget)
	cctx, cancel := context.WithTimeout(ctx, tlsCalibrationBudget)
	defer cancel()
	if r, ok := tlsshape.Ensure(cctx, tlsCalibrationFile(), network, opts, tlsCalibrationConfig()); ok {
		s.result = &r
		u.Note("%s", calibrationSummary(r))
	}
	return s
}

func calibrationSummary(r tlsshape.Result) string {
	if len(r.Gateways) == 0 {
		return "No WARP HTTP/2 gateway accepted a TCP connection: the addresses themselves are blocked, which F&F cannot change"
	}
	if !r.Reached() {
		return "No MASQUE hello reached WARP's HTTP/2 gateway directly; profiles keep their order"
	}
	pick := func(v, none string) string {
		if v == "" {
			return none
		}
		return v
	}
	return fmt.Sprintf("Best on this network: SNI %s · fingerprint %s · F&F twin %s · fragment %s",
		pick(r.SNI, "none passed"), pick(r.Fingerprint, "none passed"), pick(r.AltFingerprint, "none passed"), pick(r.Fragment, "none passed"))
}

func printTLSCalibration(u *term, r tlsshape.Result) {
	for _, t := range r.Trials {
		switch {
		case t.OK == t.Attempts && t.OK > 0:
			u.Line(toneOK, "%s · %d/%d · %.0fms", t.Shape, t.OK, t.Attempts, t.MS)
		case t.OK > 0:
			u.Line(toneWarn, "%s · %d/%d · %.0fms · %s", t.Shape, t.OK, t.Attempts, t.MS, t.Failure)
		default:
			u.Line(toneFail, "%s · 0/%d · %s", t.Shape, t.Attempts, t.Failure)
		}
	}
	u.Line(toneInfo, "%s", calibrationSummary(r))
	u.Note("A passed hello means WARP's gateway answered it; a live tunnel still decides which Aether profile wins.")
}

// runTLSCalibration measures afresh, prints every trial and saves the result.
func runTLSCalibration(ctx context.Context, u *term, opts tlsshape.Options) int {
	u.Line(toneInfo, "MASQUE hello calibration · %s", opts.Summary())
	u.Note("Direct TLS handshakes with WARP's HTTP/2 gateways; no tunnel, a few KB.")
	r := tlsshape.Calibrate(ctx, opts, tlsCalibrationConfig())
	u.Note("Gateways measured: %v", r.Gateways)
	if ctx.Err() != nil && !r.Reached() {
		u.Line(toneWarn, "Cancelled")
		return 1
	}
	printTLSCalibration(u, r)
	if err := tlsshape.Save(tlsCalibrationFile(), networkSignature(ctx), r); err != nil {
		u.Note("Not saved: %v", err)
	}
	if !r.Reached() {
		return 1
	}
	return 0
}

func runTLSCalibrate(args []string) int {
	fs := flag.NewFlagSet("tls-calibrate", flag.ContinueOnError)
	fp := fs.String("fingerprint", "auto", "auto, chrome, firefox, semi-python or go")
	sni := fs.String("sni", "auto", "auto, a MASQUE server name, or comma-separated names to compare")
	fragment := fs.String("fragment", "auto", "auto, off, or size/delay such as "+tlsshape.DefaultFragment)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	opts, err := tlsshape.ParseOptions(*fp, *sni, *fragment)
	if err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "tls-calibrate:", err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return runTLSCalibration(ctx, newTerm(os.Stdout), opts)
}

// tlsCalibrationConfig measures against the HTTP/2 gateways the core last
// connected through, then the built-in spread.
func tlsCalibrationConfig() tlsshape.Config {
	return tlsshape.Config{Candidates: tlsshape.CandidatesFrom(filepath.Join(warpDir(), "masque-lastconn.toml"))}
}
