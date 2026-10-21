package aether

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type EnrollmentRoute struct {
	Label string
	Args  []string
	// Timeout bounds this route alone; zero means DefaultRouteTimeout. A slow
	// failure of one route never spends the budget of the routes after it.
	Timeout time.Duration
}

// DefaultRouteTimeout bounds one registration route.
const DefaultRouteTimeout = 60 * time.Second

// EnrollmentBudget is the time all routes may take together, plus slack for
// staging and validation; callers bounding the whole transaction use it so a
// later fallback is never starved by an earlier slow route.
func EnrollmentBudget(routes []EnrollmentRoute) time.Duration {
	total := 5 * time.Second
	for _, r := range routes {
		total += r.timeout()
	}
	return total
}

func (r EnrollmentRoute) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultRouteTimeout
}

// EnrollmentEvent contains progress only, never registration output or keys.
type EnrollmentEvent struct {
	Protocol string `json:"protocol"`
	Route    string `json:"route"`
	Phase    string `json:"phase"`
	Attempt  int    `json:"attempt"`
	Total    int    `json:"total"`
}

type EnrollmentOptions struct {
	Binary     string
	Protocol   string
	StateDir   string
	Path       string
	Routes     []EnrollmentRoute
	Run        func(context.Context, string, []string) error
	OnProgress func(EnrollmentEvent)
}

// EnrollIdentity is the original CLI's staged registration transaction. Each
// route gets fresh private files, both identity protocols are validated offline,
// and publication never replaces an existing identity. Clients only adapt
// process execution, private paths and presentation.
func EnrollIdentity(ctx context.Context, o EnrollmentOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.Protocol != "masque" && o.Protocol != "wg" {
		return errors.New("identity protocol must be masque or wg")
	}
	if o.StateDir == "" || filepath.Dir(filepath.Clean(o.Path)) != filepath.Clean(o.StateDir) {
		return errors.New("identity must be stored in the managed private state directory")
	}
	if err := CheckIdentity(o.Path, o.Protocol); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if o.Run == nil {
		return errors.New("identity registration requires a managed core runner")
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return err
	}
	for i, route := range o.Routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir, err := os.MkdirTemp(o.StateDir, ".enroll-")
		if err != nil {
			return err
		}
		notify := func(phase string) {
			if o.OnProgress != nil {
				o.OnProgress(EnrollmentEvent{Protocol: o.Protocol, Route: route.Label, Phase: phase, Attempt: i + 1, Total: len(o.Routes)})
			}
		}
		notify("registering")
		stage := filepath.Join(dir, filepath.Base(o.Path))
		masquePath, wgPath := filepath.Join(dir, "masque.toml"), filepath.Join(dir, "wg.toml")
		if o.Protocol == "wg" {
			wgPath = stage
		} else {
			masquePath = stage
		}
		args := append([]string(nil), route.Args...)
		args = append(args, "--register", o.Protocol, "--config", filepath.Join(dir, "aether.toml"),
			"--masque-config", masquePath, "--wg-config", wgPath, "--log-level", "error")
		actx, cancel := context.WithTimeout(ctx, route.timeout())
		err = o.Run(actx, o.Binary, args)
		cancel()
		if err == nil {
			err = CheckIdentity(stage, o.Protocol)
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil {
			err = os.Chmod(stage, 0o600)
			if err == nil {
				err = os.Link(stage, o.Path)
			}
			if errors.Is(err, os.ErrExist) {
				err = CheckIdentity(o.Path, o.Protocol)
			}
			if err != nil {
				notify("save_failed")
				_ = os.RemoveAll(dir) // exact directory created by this attempt
				return fmt.Errorf("cannot publish identity: %w", err)
			}
		}
		_ = os.RemoveAll(dir)
		if err == nil {
			notify("saved")
			return nil
		}
		notify("not_registered")
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return errors.New("no registration route succeeded; API may be blocked (saved keys kept)")
}
