package aether

import (
	"strings"
	"testing"
	"time"
)

func TestGoolEnrollmentUsesOnlyOuterMasqueForBothFlagForms(t *testing.T) {
	for _, args := range [][]string{
		{"--gool", "--h2", "--gool-peer", "192.0.2.1:2408"},
		{"--protocol=gool", "--h2", "--gool-peer=192.0.2.1:2408"},
	} {
		inner := Profile{Label: "inner", Args: args}
		outer := GoolOuterProfile(inner)
		if outer.Method() != "masque-h2" || outer.Has("--gool-peer") {
			t.Fatalf("inner enrollment would recursively require its missing inner identity: %v", outer.Args)
		}
		if !strings.Contains(strings.Join(inner.Args, " "), "gool") {
			t.Fatal("outer bootstrap mutated the saved inner profile")
		}
	}
}

func TestNativeStartupDeadlinePreservesEqualsFormAndCannotOverflow(t *testing.T) {
	for _, args := range [][]string{{"--startup-secs", "100"}, {"--startup-secs=100"}} {
		if got := AttemptTimeout(Profile{Args: args}); got != 120*time.Second {
			t.Fatalf("core can be canceled before its configured startup deadline: %v", got)
		}
	}
	for _, value := range []string{"-1", "invalid", "999999999999999999999999999"} {
		if got := AttemptTimeout(Profile{Args: []string{"--startup-secs=" + value}}); got != 65*time.Second {
			t.Fatalf("invalid native startup created an unsafe timeout: %v", got)
		}
	}
}

func TestIdentityRequirementsKeepStandaloneAndNestedKeysSeparate(t *testing.T) {
	for _, flag := range []string{"--psiphon-only", "--tor-only"} {
		if len(IdentityRequirements(Profile{Args: []string{flag}})) != 0 {
			t.Fatalf("%s unexpectedly requires WARP registration", flag)
		}
	}
	for _, args := range [][]string{{"--gool"}, {"--gool-classic"}, {"--mim"}} {
		required := IdentityRequirements(Profile{Args: args})
		if len(required) != 2 || required[0].Name == required[1].Name {
			t.Fatalf("nested identity would replace the primary: %+v", required)
		}
	}
}
