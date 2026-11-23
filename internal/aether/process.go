package aether

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/coreprocess"
)

// Run is the original Aether launcher, with explicit client-owned paths and
// context. Registration output must use RunEnrollment, not a UI/log writer.
func Run(ctx context.Context, binary string, args []string, output io.Writer) error {
	cmd := coreprocess.Command(ctx, binary, args...)
	cmd.Env = managedEnvironment(args)
	cmd.Stdout, cmd.Stderr = output, output
	return coreprocess.Run(cmd)
}

func RunEnrollment(ctx context.Context, binary string, args []string) error {
	cmd := coreprocess.Command(ctx, binary, args...)
	cmd.Env = managedEnvironment(args)
	// Native registration may print account tokens and private keys.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return coreprocess.Run(cmd)
}

func InspectProfiles(ctx context.Context, binary string, profiles []Profile) ([]Profile, error) {
	help, err := inspectHelp(ctx, binary)
	if err != nil {
		return nil, err
	}
	return SupportedProfiles(profiles, help), nil
}

// InspectOptions reads capabilities from the actual executable, not a release note.
func InspectOptions(ctx context.Context, binary string) (map[string]bool, error) {
	help, err := inspectHelp(ctx, binary)
	if err != nil {
		return nil, err
	}
	return DocumentedOptions(help), nil
}

func inspectHelp(ctx context.Context, binary string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := coreprocess.Command(ctx, binary, "--help")
	var help bytes.Buffer
	cmd.Stdout = &help
	if err := coreprocess.Run(cmd); err != nil {
		return "", fmt.Errorf("cannot inspect Aether capabilities: %w", err)
	}
	return help.String(), nil
}

// KTest owns its native command line. Shell AETHER_* defaults can otherwise
// override unexpressed Chrome/fragment/peer/upstream settings and invalidate
// the measurement, or redirect registration. Preserve unrelated environment.
func managedEnvironment(args []string) []string {
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(name), "AETHER_") ||
			(strings.EqualFold(name, "RUST_LOG") && (Profile{Args: args}.Has("--log-level") || Profile{Args: args}.Has("--verbose"))) {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "AETHER_REPROVISION=0")
}
