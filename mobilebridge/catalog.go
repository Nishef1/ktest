package mobilebridge

import (
    "encoding/json"

    "github.com/Nishef1/ktest/internal/connectionpolicy"
)

// ConnectionModes exports the same connection labels and policy limitations
// that the terminal uses. It describes capabilities, not VPN readiness.
func ConnectionModes() string {
    payload := struct {
        Modes []connectionpolicy.Mode `json:"modes"`
    }{Modes: connectionpolicy.AndroidModes()}
    raw, err := json.Marshal(payload)
    if err != nil {
        return `{"modes":[]}`
    }
    return string(raw)
}
