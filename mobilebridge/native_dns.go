package mobilebridge

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/connectiondns"
)

// The standalone Go Psiphon executable cannot call Android's Java DNS APIs.
// Feed its documented alternate-resolver option from the same encrypted wire
// DNS implementation as the TUN, preserving direct QUIC bootstrap capability.
func preparePsiphonDNS(ctx context.Context, stateDir, id string) (string, func(), error) {
	exchange, closeIdle, err := connectiondns.MobilePacketDNS("fast", "")
	if err != nil {
		return "", nil, err
	}
	address, stop, err := startNativeDNS(ctx, exchange)
	if err != nil {
		closeIdle()
		return "", nil, err
	}
	raw, err := json.Marshal(map[string]any{
		"DNSResolverAlternateServers":                 []string{address},
		"DNSResolverPreferredAlternateServers":        []string{address},
		"DNSResolverPreferAlternateServerProbability": 1.0,
	})
	path := filepath.Join(stateDir, "psiphon-dns-"+id+".json")
	cleanup := func() { stop(); closeIdle(); _ = os.Remove(path) }
	if err == nil {
		err = os.WriteFile(path, raw, 0600)
	}
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func startNativeDNS(parent context.Context, exchange func(context.Context, []byte) ([]byte, error)) (string, func(), error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	closeOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	done := make(chan struct{})
	slots := make(chan struct{}, 16)
	var workers sync.WaitGroup
	go func() {
		defer close(done)
		for {
			buffer := make([]byte, 4096)
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-slots }()
				queryCtx, stop := context.WithTimeout(ctx, 8*time.Second)
				defer stop()
				response, err := exchange(queryCtx, buffer[:n])
				if err == nil && ctx.Err() == nil {
					_, _ = conn.WriteToUDP(response, peer)
				}
			}()
		}
	}()
	return conn.LocalAddr().String(), func() {
		cancel()
		closeOnCancel()
		_ = conn.Close()
		<-done
		workers.Wait()
	}, nil
}
