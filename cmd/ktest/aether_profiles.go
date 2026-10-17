package main

import (
	"context"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
)

type aetherProfile = aether.Profile

const defaultAetherProfiles = aether.DefaultProfiles

func validAetherMethod(method string) bool { return aether.ValidMethod(method) }
func parseAetherProfiles(text, ech, ip string) ([]aetherProfile, error) {
	return aether.ParseProfiles(text, ech, ip)
}
func filterAetherMethod(profiles []aetherProfile, method string) []aetherProfile {
	return aether.FilterMethod(profiles, method)
}
func profilesForMode(profiles []aetherProfile, mode ConnectionMode) []aetherProfile {
	return aether.ProfilesForMode(profiles, string(mode))
}
func aetherDocumentedOptions(help string) map[string]bool { return aether.DocumentedOptions(help) }
func aetherRunArgs(_ int, p aetherProfile, port int) []string {
	return aether.RunArgs(p, port, warpDir())
}
func attemptTimeout(p aetherProfile) time.Duration { return aether.AttemptTimeout(p) }
func supportedAetherProfiles(ctx context.Context, bin string, profiles []aetherProfile) ([]aetherProfile, error) {
	return aether.InspectProfiles(ctx, bin, profiles)
}
