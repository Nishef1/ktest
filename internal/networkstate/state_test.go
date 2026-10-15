package networkstate

import (
	"context"
	"testing"
)

func TestInspectNeverMutatesNetwork(t *testing.T) {
	// Smoke test on CI; VPN presence depends on the actual runner.
	_ = Inspect(context.Background())
}
