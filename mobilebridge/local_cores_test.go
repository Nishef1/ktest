package mobilebridge

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/coreprocess"
)

func TestFastIncludesXrayAndDefersManagedExitDiscovery(t *testing.T) {
	if !androidXrayEnabled("fast") || shouldWarmAutomaticExit("fast") {
		t.Fatal("Fast must offer Xray locally and defer foreign exit discovery until needed")
	}
	if !androidXrayEnabled("balanced") || !shouldWarmAutomaticExit("balanced") {
		t.Fatal("Balanced lost its optional Xray route or early managed-exit warmup")
	}
}

func TestManualDiagnosticsIsolateAndroidStrategies(t *testing.T) {
	strategies, err := byedpi.ParseStrategies(strings.NewReader(byedpi.DefaultStrategies))
	if err != nil {
		t.Fatal(err)
	}
	fixed := fixedAndroidStrategies(strategies)
	if len(fixed) != len(strategies) {
		t.Fatal("a strategy disappeared instead of becoming a fixed candidate")
	}
	for _, strategy := range fixed {
		for _, arg := range strategy.Args {
			if strings.HasPrefix(arg, "--auto") {
				t.Fatalf("selected native method could still change techniques live: %+v", strategy)
			}
		}
	}
	if !strings.Contains(fixed[0].Label, "fixed") || fixed[1].Label != strategies[1].Label {
		t.Fatal("fixed adaptive variants were not distinguished from unchanged methods")
	}
}

// A real child listener exercises process ownership without downloading a core.
func init() {
	if os.Getenv("KTEST_LOCAL_CORE_HELPER") != "1" {
		return
	}
	var host, port string
	for i := 1; i+1 < len(os.Args); i++ {
		switch os.Args[i] {
		case "-i":
			host = os.Args[i+1]
		case "-p":
			port = os.Args[i+1]
		}
	}
	if host != "127.0.0.1" || port == "" {
		os.Exit(2)
	}
	for _, arg := range os.Args {
		if arg == "--ktest-slow-listener" {
			time.Sleep(6 * time.Second)
		}
	}
	l, err := net.Listen("tcp4", net.JoinHostPort(host, port))
	if err != nil {
		os.Exit(3)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			os.Exit(4)
		}
		go func() {
			defer c.Close()
			var greeting [3]byte
			if _, err := io.ReadFull(c, greeting[:]); err == nil && greeting == [3]byte{5, 1, 0} {
				_, _ = c.Write([]byte{5, 0})
			}
		}()
	}
}

func TestLocalBypassCoresBindLoopbackAndAreReapedOnStop(t *testing.T) {
	t.Setenv("KTEST_LOCAL_CORE_HELPER", "1")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	set, err := startLocalCores(ctx, bin, []byedpi.Strategy{{Label: "one"}, {Label: "two"}})
	if err != nil {
		t.Fatal(err)
	}
	defer set.stop()
	if len(set.upstreams) != 2 {
		t.Fatalf("lost a working strategy: %+v", set.upstreams)
	}
	for _, u := range set.upstreams {
		if !u.LocalDNS || !u.LocalBypass || u.Exit || u.AIEligible {
			t.Fatalf("local bypass was misclassified as a foreign exit: %+v", u)
		}
		host, _, err := net.SplitHostPort(u.Addr)
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("core listener escaped loopback: %+v", u)
		}
	}
	set.stop()
	for _, u := range set.upstreams {
		c, err := net.DialTimeout("tcp", u.Addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			t.Fatalf("core survived disconnect at %s", u.Addr)
		}
	}
	if coreprocess.Count() != 0 {
		t.Fatal("disconnect left owned native processes")
	}
}

func TestAndroidProxyRejectsMissingBypassBundleBeforePublishingListeners(t *testing.T) {
	StopProxy()
	defer StopProxy()
	for _, mode := range []string{"balanced", "fast"} {
		if _, err := StartAndroidProxy(mode, "", t.TempDir()); err == nil {
			t.Fatalf("%s silently started without its bypass core", mode)
		}
		var report proxyReport
		if err := json.Unmarshal([]byte(ProxyStatus()), &report); err != nil || report.Running {
			t.Fatalf("failed startup advertised a connection: %+v, %v", report, err)
		}
	}
	if coreprocess.Count() != 0 {
		t.Fatal("failed startup left owned native processes")
	}
}

func TestAndroidByeDPIReadyStrategyIsNotBlockedByEarlierSlowCore(t *testing.T) {
	t.Setenv("KTEST_LOCAL_CORE_HELPER", "1")
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	set, err := startLocalCores(ctx, bin, []byedpi.Strategy{
		{Label: "slow", Args: []string{"--ktest-slow-listener"}},
		{Label: "healthy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer set.stop()
	if len(set.upstreams) != 1 || set.upstreams[0].Name != "ByeDPI healthy" {
		t.Fatalf("slow first core starved healthy second core: %+v", set.upstreams)
	}
}
