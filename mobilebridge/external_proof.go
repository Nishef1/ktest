package mobilebridge

import (
    "context"
    "encoding/json"
    "errors"
    "strings"
    "time"
)

type ExternalSocksProof struct {
    Verified bool `json:"verified"`
    IP string `json:"ip"`
    Region string `json:"region"`
    Explanation string `json:"explanation"`
}

// VerifyExternalSocks is a strict gate for experimental Android whole-device VPN.
// It never starts a VPN. All requests use the loopback upstream, with normal
// TLS hostname and certificate verification. The selected method's identity
// is NOT proven except for Tor's additional Tor Project check.
func VerifyExternalSocks(address, mode string) (string, error) {
    switch strings.ToLower(strings.TrimSpace(mode)) {
    case "aether", "psiphon", "tor", "balanced", "fast":
    default:
        return "", errors.New("unsupported mode for verified SOCKS exit")
    }
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()
    result, err := verifyLocalUpstream(ctx, address, mode == "tor")
    if err != nil { return "", err }
    proof := ExternalSocksProof{
        Verified: true,
        IP: result.IP,
        Region: result.Region,
        Explanation: "HTTPS request completed via supplied SOCKS5 server. Not proof of a specific transport or VPN traffic capture.",
    }
    data, err := json.Marshal(proof)
    if err != nil { return "", err }
    return string(data), nil
}
