package main

import (
 "context"
 "errors"
 "net"

 "github.com/Nishef1/ktest/internal/httpproxy"
)

// startHTTPBridge exposes ktest's existing SOCKS5 route selector as a
// loopback-only HTTP proxy for Windscribe's Proxy Settings (not Proxy Gateway).
// Failure to bind this optional port must never stop the normal SOCKS proxy.
func startHTTPBridge(ctx context.Context, listen, socks string) (string, func(), error) {
 tcp,err:=net.ResolveTCPAddr("tcp",listen)
 if err!=nil || tcp.IP==nil || !tcp.IP.IsLoopback() {return "",nil,errors.New("HTTP proxy must listen on loopback only")}
 up,err:=net.ResolveTCPAddr("tcp",socks)
 if err!=nil || up.IP==nil || !up.IP.IsLoopback() || up.Port==0 {return "",nil,errors.New("SOCKS upstream must be loopback")}
 if tcp.Port!=0 && tcp.Port==up.Port && tcp.IP.Equal(up.IP) {return "",nil,errors.New("HTTP and SOCKS port cannot be the same")}
 l,err:=net.Listen("tcp",listen)
 if err!=nil {return "",nil,err}
 go func(){_ = (&httpproxy.Server{Upstream:socks}).Serve(ctx,l)}()
 return l.Addr().String(),func(){_ =l.Close()},nil
}
