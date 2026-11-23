package revive

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

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

// VerifyPinnedSubscriptionFile requires byte-identical bundled data. The
// running profile is selected from the compiled-in bytes, not this file.
func VerifyPinnedSubscriptionFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read pinned Serverless subscription: %w", err)
	}
	if !bytes.Equal(content, pinnedServerlessV65) {
		return errors.New("Serverless profile differs from the pinned upstream v65")
	}
	return nil
}

// SelectPinnedProfileForFamily preserves the vetted source subscription;
// in single-family mode the Go proxy supplies already validated numeric
// destinations. Xray must not replace them with SNI names or CDN redirects.
func SelectPinnedProfileForFamily(variant string, port int, family string) ([]byte, error) {
	payload, err := SelectPinnedProfileOnPort(variant, port)
	if err != nil {
		return nil, err
	}
	return constrainProfileFamily(payload, family)
}

func constrainProfileFamily(payload []byte, family string) ([]byte, error) {
	if family == "" || family == "both" {
		return payload, nil
	}
	if family != "ipv4" && family != "ipv6" {
		return nil, errors.New("invalid Serverless destination family")
	}
	var config map[string]any
	if err := json.Unmarshal(payload, &config); err != nil {
		return nil, err
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return nil, errors.New("expected one pinned Serverless inbound")
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		return nil, errors.New("invalid Serverless inbound")
	}
	if sniffing, ok := inbound["sniffing"].(map[string]any); ok {
		sniffing["routeOnly"] = true
		// FakeDNS destination replacement is incompatible with a numeric-only inlet.
		if overrides, ok := sniffing["destOverride"].([]any); ok {
			filtered := make([]any, 0, len(overrides))
			for _, item := range overrides {
				if item != "fakedns" {
					filtered = append(filtered, item)
				}
			}
			sniffing["destOverride"] = filtered
		}
	}
	// Numeric destination enforcement cannot operate on fake DNS addresses.
	// Keep the original real DNS chain but remove its fake-IP server.
	if dns, ok := config["dns"].(map[string]any); ok {
		if servers, ok := dns["servers"].([]any); ok {
			filtered := make([]any, 0, len(servers))
			for _, item := range servers {
				if server, ok := item.(map[string]any); ok && server["address"] == "fakedns" {
					continue
				}
				filtered = append(filtered, item)
			}
			dns["servers"] = filtered
		}
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return nil, errors.New("missing Serverless outbounds")
	}
	for _, item := range outbounds {
		outbound, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid Serverless outbound")
		}
		if settings, ok := outbound["settings"].(map[string]any); ok {
			// A direct CDN redirect can re-resolve to the opposite family.
			// Preserve the numeric application destination instead.
			delete(settings, "redirect")
		}
	}
	return json.MarshalIndent(config, "", "  ")
}
