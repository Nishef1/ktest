package mobilebridge

import (
    "context"
    "encoding/json"
    "encoding/hex"
    "time"

    "github.com/Nishef1/ktest/internal/front"
)

// ProbeECH checks whether a fresh, DNS-independent Cloudflare ECH
// retry config can be obtained. It does not claim to tunnel app traffic.
func ProbeEch() (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
    defer cancel()
    cfg, addr, err := front.FetchCloudflareECH(ctx)
    if err != nil { return "", err }
    v := struct {
        Edge string `json:"edge"`
        ECHConfigBytes int `json:"ech_config_bytes"`
        Prefix string `json:"config_prefix"`
        Note string `json:"note"`
    }{Edge: addr, ECHConfigBytes: len(cfg), Prefix: hex.EncodeToString(cfg[:min(len(cfg), 16)]),
      Note: "An ECH retry configuration was obtained; a usable network tunnel was not verified."}
    b, err := json.Marshal(v)
    return string(b), err
}
