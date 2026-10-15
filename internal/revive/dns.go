package revive

import (
	"encoding/json"
	"fmt"
	"strings"
)

// improveDNSBootstrap avoids a single hard dependency on Cloudflare DoH.
// Native DNS is used only for known reachable Google domains, not YouTube.
// Restricted domains try Google DoH and then the original Cloudflare DoH.
// This alters no routing, fragmentation, certificates or OS DNS settings.
func improveDNSBootstrap(root map[string]json.RawMessage) error {
	raw := root["dns"]
	if len(raw) == 0 {
		return nil
	}
	var dns map[string]json.RawMessage
	if err := json.Unmarshal(raw, &dns); err != nil {
		return fmt.Errorf("invalid profile dns: %w", err)
	}
	var servers []map[string]json.RawMessage
	if err := json.Unmarshal(dns["servers"], &servers); err != nil {
		return fmt.Errorf("invalid profile dns servers: %w", err)
	}
	index := -1
	for i, server := range servers {
		var address string
		if err := json.Unmarshal(server["address"], &address); err != nil {
			continue
		}
		if strings.EqualFold(address, "https://cloudflare-dns.com/dns-query") {
			index = i
			break
		}
	}
	if index < 0 {
		return nil // an unknown DNS topology is untouched
	}
	local := map[string]any{
		"tag": "domestic-dns",
		"address": "localhost",
		"domains": []string{
			"domain:google.com", "domain:googleapis.com",
			"domain:gstatic.com", "full:dns.google",
		},
		"skipFallback": true,
		"timeoutMs": 3500,
		"finalQuery": true,
	}
	alternate := map[string]any{
		"tag": "no-filter-dns",
		"address": "https://dns.google/dns-query",
		"timeoutMs": 4500,
		"finalQuery": false,
	}
	localBytes, err := json.Marshal(local)
	if err != nil {
		return err
	}
	alternateBytes, err := json.Marshal(alternate)
	if err != nil {
		return err
	}
	var localMap, alternateMap map[string]json.RawMessage
	if err := json.Unmarshal(localBytes, &localMap); err != nil {
		return err
	}
	if err := json.Unmarshal(alternateBytes, &alternateMap); err != nil {
		return err
	}
	servers[index]["timeoutMs"] = json.RawMessage("4500")
	modified := make([]map[string]json.RawMessage, 0, len(servers)+2)
	modified = append(modified, servers[:index]...)
	modified = append(modified, localMap, alternateMap)
	modified = append(modified, servers[index:]...)
	encoded, err := json.Marshal(modified)
	if err != nil {
		return err
	}
	dns["servers"] = encoded
	encoded, err = json.Marshal(dns)
	if err != nil {
		return err
	}
	root["dns"] = encoded
	return nil
}
