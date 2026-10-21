package mobilebridge

import "sync/atomic"

// aiPolicyOff mirrors the Android "AI policy" switch (on by default). Off
// routes AI and TikTok like any other site; Psiphon/Tor exit-only rules and
// Aether's exit-only carriage are unaffected. Read when a proxy starts.
var aiPolicyOff atomic.Bool

// SetAIPolicy is called by the app before each connection.
func SetAIPolicy(enabled bool) { aiPolicyOff.Store(!enabled) }

func aiPolicyEnabled() bool { return !aiPolicyOff.Load() }
