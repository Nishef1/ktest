package revive

import _ "embed"

// The upstream Serverless-for-Iran v65 subscription is GPL-3.0 config data.
// Source: patterniha/Serverless-for-Iran at 9b62ddf9e8bc83432d4b0bcf8be4c963bc8cb300.
// Pinned Git blob: eac9ad0260d0c886b2118cf8590f866e862bfe82.
//
//go:embed subscription-v65.json
var pinnedServerlessV65 []byte

// SelectPinnedProfileOnPort selects a published A/B/OOB profile and forces
// its only SOCKS/HTTP inbound onto loopback, without changing its routing.
func SelectPinnedProfileOnPort(variant string, port int) ([]byte, error) {
	return SelectProfileOnPort(pinnedServerlessV65, variant, "", port)
}
