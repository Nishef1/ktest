package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A confirmation means Windscribe CLI transitioned to Connected while a
// unique eligible carrier session was active. This is stronger than an
// OpenVPN-shaped response but is not cryptographic proof of socket identity.
type wsConfirmation struct {
	At       time.Time `json:"at"`
	Target   string    `json:"target"`
	Location string    `json:"location,omitempty"`
	Method   string    `json:"method"`
	Carrier  string    `json:"carrier"`
	Attempt  uint64    `json:"attempt"`
}

type wsHistoryMethod struct {
	Name             string `json:"name"`
	VariantsStarted  int    `json:"variants_started"`
	VariantsChecked  int    `json:"variants_checked"`
	VariantsFailed   int    `json:"variants_failed"`
	OpenVPNReplies   int    `json:"openvpn_replies"`
	CLIConfirmations int    `json:"cli_confirmations"`
}

type wsHistoryTarget struct {
	Target   string            `json:"target"`
	Location string            `json:"location,omitempty"`
	Methods  []wsHistoryMethod `json:"methods"`
}

type wsHistoryRecord struct {
	Version       int               `json:"version"`
	StartedAt     time.Time         `json:"started_at"`
	EndedAt       time.Time         `json:"ended_at"`
	Targets       []wsHistoryTarget `json:"targets"`
	Confirmations []wsConfirmation  `json:"confirmations"`
}

// Each newline is one session, including unsuccessful sessions; without the
// exposure counts, ranking methods by successes alone would be misleading.
// These records contain target IPs, SNI and carrier endpoints; keep local.
func appendWSHistory(path string, record wsHistoryRecord) error {
	if path == "" {
		return nil
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode Windscribe history: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create Windscribe history directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open Windscribe history: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("append Windscribe history: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync Windscribe history: %w", err)
	}
	return nil
}

func wsCarrierDetails(carrier string) (transport, sni, entry, hello string) {
	switch {
	case strings.HasPrefix(carrier, "WStunnel "):
		transport = "WStunnel"
	case strings.HasPrefix(carrier, "Stealth "):
		transport = "Stealth"
	case strings.HasPrefix(carrier, "CDN "):
		transport = "CDN"
	default:
		transport = "unknown"
	}
	for _, field := range strings.Fields(carrier) {
		switch {
		case strings.HasPrefix(field, "sni="):
			sni = strings.TrimPrefix(field, "sni=")
		case strings.HasPrefix(field, "entry="):
			entry = strings.TrimPrefix(field, "entry=")
		case strings.HasPrefix(field, "hello="):
			hello = strings.TrimPrefix(field, "hello=")
		}
	}
	return
}
