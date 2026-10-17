package mobilebridge

import (
    "encoding/json"
    "net"
    "testing"
)

func TestProxyStartsAndStopsWithRealLoopbackListeners(t *testing.T) {
    defer StopProxy()
    if _, err := StartProxy("tor"); err == nil {
        t.Fatal("unsupported mode should never be reported connected")
    }
    data, err := StartProxy("balanced")
    if err != nil { t.Fatal(err) }
    var status proxyReport
    if err := json.Unmarshal([]byte(data), &status); err != nil { t.Fatal(err) }
    if !status.Running || status.Coverage != "proxy" || status.Mode != "balanced" {
        t.Fatalf("unexpected status: %+v", status)
    }
    for _, addr := range []string{status.Socks, status.HTTP} {
        host, _, err := net.SplitHostPort(addr)
        if err != nil || host != "127.0.0.1" { t.Fatalf("listener not loopback: %q (%v)", addr, err) }
        conn, err := net.Dial("tcp", addr)
        if err != nil { t.Fatal(err) }
        _ = conn.Close()
    }
    if _, err := StartProxy("fast"); err == nil { t.Fatal("mode change without disconnect must fail") }
    StopProxy()
    if got := ProxyStatus(); !json.Valid([]byte(got)) { t.Fatalf("invalid status: %s", got) }
    if _, err := StartProxy("fast"); err != nil { t.Fatal(err) }
}
