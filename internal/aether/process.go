package aether

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Nishef1/ktest/internal/coreprocess"
)

// Run is the original Aether launcher, with explicit client-owned paths and
// context. Registration output must use RunEnrollment, not a UI/log writer.
func Run(ctx context.Context, binary string, args []string, output io.Writer) error {
	cmd := coreprocess.Command(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "AETHER_REPROVISION=0")
	cmd.Stdout, cmd.Stderr = output, output
	return coreprocess.Run(cmd)
}

func RunEnrollment(ctx context.Context, binary string, args []string) error {
	cmd := coreprocess.Command(ctx, binary, args...)
	// Native registration may print account tokens and private keys.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return coreprocess.Run(cmd)
}

func InspectProfiles(ctx context.Context, binary string, profiles []Profile) ([]Profile, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := coreprocess.Command(ctx, binary, "--help")
	var help bytes.Buffer
	cmd.Stdout = &help
	if err := coreprocess.Run(cmd); err != nil {
		return nil, fmt.Errorf("cannot inspect Aether capabilities: %w", err)
	}
	return SupportedProfiles(profiles, help.String()), nil
}
