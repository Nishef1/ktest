package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// ByeDPI readiness is stronger than an open TCP port: its SOCKS5 greeting
// must be answered. A foreign or half-started listener must not enter the race.
func TestWaitForByeDPIRequiresRealSOCKSGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var input [3]byte
				if _, err := io.ReadFull(conn, input[:]); err != nil {
					return
				}
				if input != [3]byte{5, 1, 0} {
					return
				}
				_, _ = conn.Write([]byte{5, 0})
			}()
		}
	}()
	if !waitForByeDPI(context.Background(), done, port, time.Second) {
		t.Fatalf("healthy SOCKS5 listener at %s was rejected", fmt.Sprint(port))
	}
}

func TestWaitForByeDPIRejectsTCPOnlyListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	if waitForByeDPI(context.Background(), make(chan struct{}), port, 350*time.Millisecond) {
		t.Fatal("bare TCP accept incorrectly marked ByeDPI ready")
	}
}
