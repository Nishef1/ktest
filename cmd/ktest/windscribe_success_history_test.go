package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWindscribeHistoryRecordsOnlyCLIConnectedMethod(t *testing.T) {
	var output bytes.Buffer
	b := testBridge(&dialLog{})
	b.view = &wsProgressView{t: plainTerm(&output)}
	b.historyPath = filepath.Join(t.TempDir(), "cache", "windscribe-method-history.jsonl")
	name := "WStunnel sni=www.speedtest.net +ByeDPI split + disorder entry=192.0.2.10 hello=chrome"
	b.candidates = func(string) []wsCarrier {
		return []wsCarrier{{
			name: name, method: "ByeDPI split + disorder", addr: "192.0.2.10:443",
			open: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return fakeServer("controlled", 0, false, nil), nil
			},
		}}
	}
	conn, done, err := b.race(context.Background(), "203.0.113.10", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// An OpenVPN response alone must not become a success.
	if len(b.confirmations) != 0 {
		t.Fatal("initial OpenVPN reply recorded as VPN success")
	}
	b.observeCLIConnected()
	b.observeCLIConnected() // duplicate notification must not count twice
	done(30*time.Second, 100<<10)
	if len(b.confirmations) != 1 {
		t.Fatalf("duplicate or missing CLI confirmation: %+v", b.confirmations)
	}
	if s := b.progressSnapshot("203.0.113.10:443"); s.connected != 0 {
		t.Fatal("ended session still counted as active")
	}
	b.reportProgress()
	for _, want := range []string{"Method: ByeDPI split + disorder", "Transport: WStunnel", "SNI: www.speedtest.net", "Hello: chrome", "192.0.2.10", "Method history saved locally:"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q from summary: %s", want, output.String())
		}
	}
	raw, err := os.ReadFile(b.historyPath)
	if err != nil {
		t.Fatal(err)
	}
	var record wsHistoryRecord
	if err := json.Unmarshal(bytes.TrimSpace(raw), &record); err != nil {
		t.Fatal(err)
	}
	if record.Version != 1 || len(record.Confirmations) != 1 || len(record.Targets) != 1 {
		t.Fatalf("wrong session evidence %+v", record)
	}
	confirmed := record.Confirmations[0]
	if confirmed.Method != "ByeDPI split + disorder" || confirmed.Target != "203.0.113.10:443" || confirmed.Carrier != name {
		t.Fatalf("lost confirmed method and carrier: %+v", confirmed)
	}
	if len(record.Targets[0].Methods) != 1 {
		t.Fatalf("lost method coverage %+v", record.Targets[0])
	}
	method := record.Targets[0].Methods[0]
	if method.VariantsStarted != 1 || method.VariantsChecked != 1 || method.CLIConfirmations != 1 {
		t.Fatalf("history counters wrong %+v", method)
	}
}

func TestWindscribeUnverifiedRepliesDoNotCountAsSuccess(t *testing.T) {
	var output bytes.Buffer
	b := testBridge(&dialLog{}, carrierSpec{name: "Stealth sni=example.com entry=192.0.2.20 hello=windscribe"})
	b.view = &wsProgressView{t: plainTerm(&output)}
	b.historyPath = filepath.Join(t.TempDir(), "cache", "windscribe-method-history.jsonl")
	conn, done, err := b.race(context.Background(), "203.0.113.20", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done(time.Second, 1024)
	b.reportProgress()
	if !strings.Contains(output.String(), "no CLI-correlated VPN connection") {
		t.Fatalf("false VPN success summary: %s", output.String())
	}
	raw, err := os.ReadFile(b.historyPath)
	if err != nil {
		t.Fatal(err)
	}
	var record wsHistoryRecord
	if err := json.Unmarshal(bytes.TrimSpace(raw), &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Confirmations) != 0 || len(record.Targets) != 1 || len(record.Targets[0].Methods) == 0 {
		t.Fatalf("unverified reply was not recorded correctly: %+v", record)
	}
	m := record.Targets[0].Methods[0]
	if m.CLIConfirmations != 0 || m.OpenVPNReplies != 1 {
		t.Fatalf("OpenVPN reply was credited as a VPN connection: %+v", m)
	}
}

func TestWindscribeHistoryAppendsOneRecordPerSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache", "session-history.jsonl")
	for i := 0; i < 2; i++ {
		rec := wsHistoryRecord{Version: 1, EndedAt: time.Now().UTC()}
		if err := appendWSHistory(path, rec); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected two append-only sessions; got %d", len(lines))
	}
	for _, line := range lines {
		if !json.Valid(line) {
			t.Fatalf("invalid session JSON: %s", line)
		}
	}
}
