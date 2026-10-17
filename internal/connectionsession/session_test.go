package connectionsession

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestListenerFailureStopsWholeSessionAndClosesStreams(t *testing.T) {
	proxy, err := smartproxy.New(smartproxy.Config{Upstreams: smartproxy.PlainUpstreams()})
	if err != nil {
		t.Fatal(err)
	}
	session, err := Start(context.Background(), proxy, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Stop()
	httpAddress, err := session.StartHTTP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp", httpAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = session.SOCKS.Close() // reproduce a failed core listener
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("HTTP survived failed SOCKS listener")
	}
	session.Stop()
	if session.Err() == nil {
		t.Fatal("lost failure cause")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("existing stream survived session failure")
	}
	if _, err := session.StartProbes(); err == nil {
		t.Fatal("stopped session reopened a listener")
	}
}
