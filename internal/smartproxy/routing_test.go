package smartproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExactDestinationHistoryAndHysteresis(t *testing.T) {
	p, _ := New(Config{Upstreams: []Upstream{{Name: "a"}, {Name: "b", Rank: 1}}, Stagger: 80 * time.Millisecond})
	a, b := p.ups[0], p.ups[1]
	p.record(a, "api.example.org", "443", true, 100*time.Millisecond)
	p.record(b, "assets.example.org", "443", true, 20*time.Millisecond)
	p.record(b, "api.example.org", "8443", true, 20*time.Millisecond)
	if p.rememberedName("api.example.org", "443") != "a" {
		t.Fatal("a sibling or port overwrote the winner")
	}
	if p.hasMemory("fresh.example.org", "443") {
		t.Fatal("group hint became exact history")
	}
	p.record(b, "api.example.org", "443", true, 20*time.Millisecond)
	if p.rememberedName("api.example.org", "443") != "a" {
		t.Fatal("one concurrent faster result replaced a proven route")
	}
	p.record(b, "api.example.org", "443", true, 20*time.Millisecond)
	if p.rememberedName("api.example.org", "443") != "b" {
		t.Fatal("repeated substantial improvement was ignored")
	}
	p.record(b, "api.example.org", "443", false, time.Second)
	if p.rememberedName("api.example.org", "443") != "b" {
		t.Fatal("one transient failure erased the winner")
	}
	p.record(b, "api.example.org", "443", false, time.Second)
	if p.order("api.example.org", "443")[0].Name != "a" {
		t.Fatal("repeated failures did not demote the route")
	}
	p.record(a, "slow.example.net", "443", true, time.Second)
	if got := p.firstWave(a, "new.example.net", "443"); got != 80*time.Millisecond {
		t.Fatalf("another host changed timing: %s", got)
	}
}

func TestSlowRememberedRouteDoesNotDelayAFasterAlternative(t *testing.T) {
	var slow, fast atomic.Int32
	events := make(chan Event, 1)
	p, _ := New(Config{Upstreams: []Upstream{
		{Name: "remembered", Addr: silentSocks(t, &slow)},
		{Name: "alternative", Addr: fakeSocks(t, destination(t), true, &fast), Rank: 1},
	}, Stagger: 80 * time.Millisecond, FirstByteTimeout: 2 * time.Second, OnEvent: func(e Event) { events <- e }})
	p.record(p.ups[0], "recover.example", "443", true, 700*time.Millisecond)
	began := time.Now()
	w, err := p.race(context.Background(), "recover.example", "443", clientHello())
	if err != nil {
		t.Fatal(err)
	}
	w.release()
	elapsed := time.Since(began)
	if elapsed > 350*time.Millisecond {
		t.Fatalf("remembered route imposed an exclusive wait: %s", elapsed)
	}
	e := <-events
	if e.Took < 70*time.Millisecond || e.Took > elapsed {
		t.Fatalf("reported %s excludes race waiting; actual %s", e.Took, elapsed)
	}
	t.Logf("recovered in %s; reported %s", elapsed, e.Took)
}

type rejectedSession struct{}

func (rejectedSession) Serve(net.Conn, []byte) error {
	return fmt.Errorf("remote error: tls: unknown certificate")
}
func (rejectedSession) Close() {}

func TestProbeOriginSurvivesAClientClosingBeforeItsRaceCompletes(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	events := make(chan Event, 4)
	p, _ := New(Config{OnEvent: func(e Event) { events <- e }, Upstreams: []Upstream{{Name: "probe route", Takeover: func(ctx context.Context, _, _ string, _ []byte) (Session, error) {
		close(started)
		select {
		case <-release:
			return rejectedSession{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}}})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.ServeProbes(ctx, l)
	c, err := DialVia(ctx, l.Addr().String(), "probe.example", "443", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write(clientHello())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe never started")
	}
	c.Close()
	close(release)
	select {
	case e := <-events:
		if !e.Probe || !e.OK {
			t.Fatalf("late result lost probe attribution: %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no late race event")
	}
}

func TestRejectedTakeoverUsesAnAlternativeOnTheNextConnection(t *testing.T) {
	var hits atomic.Int32
	events := make(chan Event, 8)
	p, _ := New(Config{Upstreams: []Upstream{
		{Name: "front", Takeover: func(context.Context, string, string, []byte) (Session, error) { return rejectedSession{}, nil }},
		{Name: "end-to-end", Addr: fakeSocks(t, destination(t), true, &hits), Rank: 1,
			Send: func(c net.Conn, flight []byte) error {
				time.Sleep(120 * time.Millisecond)
				_, err := c.Write(flight)
				return err
			}},
	}, Stagger: 40 * time.Millisecond, OnEvent: func(e Event) { events <- e }})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)
	c, err := DialVia(ctx, l.Addr().String(), "refused.example", "443", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(clientHello())
	for {
		select {
		case e := <-events:
			if !e.Rejected {
				continue
			}
			if got := p.order("refused.example", "443")[0].Name; got != "end-to-end" {
				t.Fatalf("rejected takeover still preferred: %s", got)
			}
			if hits.Load() != 0 {
				t.Fatal("request replayed after the takeover answered")
			}
			w, err := p.race(ctx, "refused.example", "443", clientHello())
			if err != nil {
				t.Fatal(err)
			}
			defer w.release()
			if w.path != "end-to-end" {
				t.Fatalf("rejected takeover beat the slower healthy route on the next connection: %s", w.path)
			}
			return
		case <-time.After(2 * time.Second):
			t.Fatal("no refusal event")
		}
	}
}

func TestRejectedTakeoverCannotBeRelearnedByAnInFlightAttempt(t *testing.T) {
	p, _ := New(Config{Upstreams: []Upstream{
		{Name: "front", Takeover: func(context.Context, string, string, []byte) (Session, error) { return rejectedSession{}, nil }},
		{Name: "end-to-end", Rank: 1},
	}})
	front, direct := p.ups[0], p.ups[1]
	p.record(front, "api.example.org", "443", true, time.Millisecond)
	p.rejectTakeover("api.example.org", "443", "front")
	p.record(direct, "api.example.org", "443", true, 300*time.Millisecond)
	if p.record(front, "api.example.org", "443", true, time.Millisecond) {
		t.Fatal("a concurrently prepared takeover was accepted after the client rejected it")
	}
	if got := p.rememberedName("api.example.org", "443"); got != "end-to-end" {
		t.Fatalf("refused takeover replaced the healthy winner: %s", got)
	}
	if got := p.order("api.example.org", "443"); len(got) != 1 || got[0].Name != "end-to-end" {
		t.Fatal("refused takeover is still a fallback candidate")
	}
	if got := p.order("assets.example.org", "443"); len(got) != 2 {
		t.Fatal("one destination's refusal disabled fronting for another destination")
	}
}

func TestConcurrentProtectedConnectionsAcceptOnlyOneExitRoute(t *testing.T) {
	p, _ := New(Config{ExitOnly: func(string) bool { return true }, Upstreams: []Upstream{
		{Name: "exit-a", Exit: true, AIEligible: true}, {Name: "exit-b", Exit: true, AIEligible: true},
	}})
	start := make(chan struct{})
	accepted := make(chan string, 64)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			u := p.ups[i%2]
			if p.record(u, "ai.example", "443", true, time.Millisecond) {
				accepted <- u.Name
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(accepted)
	identities := map[string]bool{}
	for name := range accepted {
		identities[name] = true
	}
	if len(identities) != 1 {
		t.Fatalf("accepted multiple identities: %v", identities)
	}
}

func TestCanceledRaceAndClientAlertDoNotPoisonRouteHistory(t *testing.T) {
	p, _ := New(Config{Upstreams: []Upstream{{Name: "a"}, {Name: "b"}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.race(ctx, "cancel.example", "443", clientHello()); err == nil {
		t.Fatal("canceled race accepted")
	}
	for _, s := range p.Stats() {
		if s.Wins != 0 || s.Failures != 0 {
			t.Fatal("cancellation changed route scores")
		}
	}
	p.record(p.ups[0], "alert.example", "443", true, time.Millisecond)
	for i := 0; i < 3; i++ {
		p.observeRelay(context.Background(), "alert.example", "443", "a", relayResult{remoteFirst: true, up: 7, elapsed: time.Millisecond})
	}
	if got := p.order("alert.example", "443")[0].Name; got != "a" {
		t.Fatal("small client TLS alert penalized the route")
	}
}

func silentSocks(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, _, err := socksRequest(c); err != nil {
					return
				}
				hits.Add(1)
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String()
}

func TestSmallWaveSavesAttemptsAndFullFallbackStillReachesTheLastRoute(t *testing.T) {
	for _, goodIndex := range []int{1, 19} {
		t.Run(fmt.Sprint(goodIndex), func(t *testing.T) {
			dest := destination(t)
			var hits [20]atomic.Int32
			var ups []Upstream
			for i := range hits {
				addr := silentSocks(t, &hits[i])
				u := Upstream{Name: fmt.Sprint("route-", i), Addr: addr, Rank: i}
				if i == goodIndex {
					u.Addr = fakeSocks(t, dest, true, &hits[i])
					u.Send = func(c net.Conn, f []byte) error { time.Sleep(25 * time.Millisecond); _, err := c.Write(f); return err }
				}
				ups = append(ups, u)
			}
			p, _ := New(Config{Upstreams: ups, Stagger: 50 * time.Millisecond, FirstByteTimeout: time.Second})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			began := time.Now()
			win, err := p.race(ctx, "race.example", "443", clientHello())
			if err != nil {
				t.Fatal(err)
			}
			defer win.release()
			if !bytes.Equal(win.first, serverHello) {
				t.Fatalf("reply %x", win.first)
			}
			attempts := int32(0)
			for i := range hits {
				attempts += hits[i].Load()
			}
			if goodIndex == 1 && attempts > 3 {
				t.Fatalf("short successful race opened %d of 20 routes", attempts)
			}
			if time.Since(began) > 1500*time.Millisecond {
				t.Fatal("fallback incurred serial delays")
			}
			t.Logf("working index=%d attempts=%d elapsed=%s", goodIndex, attempts, time.Since(began))
		})
	}
}

func TestEarlyCloseFeedbackDemotesRouteWithoutReplayingRequests(t *testing.T) {
	var requests [2]atomic.Int32
	makeDest := func(good bool, index int) string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					if _, err := c.Read(make([]byte, 4096)); err != nil {
						return
					}
					_, _ = c.Write(serverHello)
					if _, err := io.ReadFull(c, make([]byte, 64)); err != nil {
						return
					}
					requests[index].Add(1)
					if good {
						_, _ = c.Write([]byte("post-hello response"))
					}
				}()
			}
		}()
		return l.Addr().String()
	}
	bad, good := makeDest(false, 0), makeDest(true, 1)
	var a, b atomic.Int32
	events := make(chan Event, 32)
	p, _ := New(Config{Upstreams: []Upstream{{Name: "bad", Addr: fakeSocks(t, bad, true, &a)}, {Name: "backup", Addr: fakeSocks(t, good, true, &b), Rank: 1}}, Stagger: 100 * time.Millisecond, OnEvent: func(e Event) { events <- e }})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if err := socksConnect(c, "quality.example", "443"); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(clientHello())
		if _, err := io.ReadFull(c, make([]byte, len(serverHello))); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(make([]byte, 64))
		data, _ := io.ReadAll(c)
		_ = c.Close()
		if i < 2 {
			deadline := time.After(time.Second)
		waitEarly:
			for {
				select {
				case e := <-events:
					if e.EarlyClose {
						break waitEarly
					}
				case <-deadline:
					t.Fatal("missing early-close feedback")
				}
			}
		} else if string(data) != "post-hello response" {
			t.Fatalf("backup not selected: %q", data)
		}
	}
	if requests[0].Load() != 2 || requests[1].Load() != 1 {
		t.Fatalf("application requests were replayed or route not demoted: bad=%d backup=%d", requests[0].Load(), requests[1].Load())
	}
}
