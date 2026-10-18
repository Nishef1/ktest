package byedpi

import (
	"context"
	"io"
	"net"
	"time"
)

// WaitReady verifies the actual SOCKS5 no-auth greeting, not merely whether a
// TCP port is open. Both the desktop and Android ByeDPI launchers use it.
// It never sends a destination or application data to the proxy.
func WaitReady(ctx context.Context, done <-chan struct{}, address string) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		case <-done:
			return false
		default:
		}
		dctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", address)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
			stop := context.AfterFunc(dctx, func() { _ = conn.Close() })
			_, err = conn.Write([]byte{5, 1, 0})
			var answer [2]byte
			if err == nil {
				_, err = io.ReadFull(conn, answer[:])
			}
			stop()
			_ = conn.Close()
			if err == nil && answer == [2]byte{5, 0} && ctx.Err() == nil {
				select {
				case <-done:
					// The process exited immediately after answering the probe.
				default:
					cancel()
					return true
				}
			}
		}
		cancel()
		timer := time.NewTimer(40 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-done:
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}
