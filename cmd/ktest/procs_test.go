package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHelperHoldsPort is the child process of the cleanup tests: it listens on
// a loopback port, reports it and sleeps until it is killed.
func TestHelperHoldsPort(t *testing.T) {
	if os.Getenv("KTEST_HELPER_PORT") != "1" {
		return
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(3)
	}
	fmt.Println("PORT", l.Addr().(*net.TCPAddr).Port)
	time.Sleep(time.Minute)
}

func startPortHolder(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldsPort$")
	cmd.Env = append(os.Environ(), "KTEST_HELPER_PORT=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "PORT "); ok {
			port, _ := strconv.Atoi(rest)
			return cmd, port
		}
	}
	t.Fatal("helper did not report a port")
	return nil, 0
}

func TestReapTrackedEndsACoreAndFreesItsPort(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestHelperHoldsPort$")
	cmd.Env = append(os.Environ(), "KTEST_HELPER_PORT=1")
	out, _ := cmd.StdoutPipe()
	configureEnrollmentProcess(cmd)
	done := make(chan error, 1)
	go func() { done <- runTracked(cmd) }()
	sc := bufio.NewScanner(out)
	port := 0
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "PORT "); ok {
			port, _ = strconv.Atoi(rest)
			break
		}
	}
	if port == 0 {
		t.Fatal("helper did not report a port")
	}
	if portFree(port) == nil {
		t.Fatal("port should be held by the core")
	}
	if trackedCount() != 1 {
		t.Fatalf("tracked = %d, want 1", trackedCount())
	}
	if reapTracked() != 1 {
		t.Fatal("reap did not see the core")
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("core survived reapTracked")
	}
	if !waitTrackedGone(context.Background(), 2*time.Second) {
		t.Fatal("core still registered after it exited")
	}
	deadline := time.Now().Add(3 * time.Second)
	for portFree(port) != nil {
		if time.Now().After(deadline) {
			t.Fatal("port still held after the core was reaped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestConfirmPortsReleasedEndsLeftoversButIgnoresForeignPorts(t *testing.T) {
	// A port busy before the session belongs to someone else and is not touched.
	foreign, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	foreignPort := foreign.Addr().(*net.TCPAddr).Port

	defer func(d time.Duration) { portReleaseWait = d }(portReleaseWait)
	portReleaseWait = 300 * time.Millisecond
	cmd, port := startPortHolder(t)
	var out syncBuffer
	menu := &terminal{ui: plainTerm(&out)}
	// The leftover core is not registered, so this only reports it.
	menu.confirmPortsReleased([]int{port, foreignPort}, map[int]bool{foreignPort: true})
	if !strings.Contains(out.String(), "still in use") || !strings.Contains(out.String(), strconv.Itoa(port)) || strings.Contains(out.String(), strconv.Itoa(foreignPort)) {
		t.Fatalf("report = %q", out.String())
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	out = syncBuffer{}
	menu.confirmPortsReleased([]int{port, foreignPort}, map[int]bool{foreignPort: true})
	if strings.Contains(out.String(), "still in use") || !strings.Contains(out.String(), "ports are free") {
		t.Fatalf("clean session reported a problem: %q", out.String())
	}
}

func TestIsYesAcceptsOnlyYAndYes(t *testing.T) {
	for in, want := range map[string]bool{"y": true, "Y": true, "yes": true, " YES ": true, "": false, "n": false, "yep": false, "0": false} {
		if isYes(in) != want {
			t.Fatalf("isYes(%q) != %t", in, want)
		}
	}
}

func TestSessionPortCleanupCoversAllCustomAetherProfilesAndGool(t *testing.T) {
	o := connectOptions{listen: "127.0.0.1:10800", httpListen: "127.0.0.1:10801"}
	ports := sessionPorts(o)
	want := map[int]bool{
		10800: true, 10801: true,
		aetherPort(0): true, aetherPort(63): true, aetherPort(80): true,
	}
	for _, port := range ports {
		delete(want, port)
	}
	if len(want) != 0 {
		t.Fatalf("missing allocated Aether/bridge ports from terminal cleanup: %v", want)
	}
}
