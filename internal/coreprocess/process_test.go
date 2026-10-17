package coreprocess

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOwnedProcessHelper(t *testing.T) {
	switch os.Getenv("KTEST_CORE_PROCESS_HELPER") {
	case "child":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(os.Getenv("KTEST_CORE_PROCESS_FILE"), []byte(fmt.Sprintf("%d %d", os.Getpid(), listener.Addr().(*net.TCPAddr).Port)), 0600); err != nil {
			os.Exit(4)
		}
		time.Sleep(time.Minute)
	case "parent", "orphan-parent":
		cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessHelper$")
		cmd.Env = append(os.Environ(), "KTEST_CORE_PROCESS_HELPER=child")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			os.Exit(5)
		}
		if os.Getenv("KTEST_CORE_PROCESS_HELPER") == "orphan-parent" {
			for i := 0; i < 500; i++ {
				if _, err := os.Stat(os.Getenv("KTEST_CORE_PROCESS_FILE")); err == nil {
					os.Exit(0)
				}
				time.Sleep(10 * time.Millisecond)
			}
			os.Exit(6)
		}
		_ = cmd.Wait()
	}
}

func TestManagedCoreEndsDescendantsOnCancelAndParentExit(t *testing.T) {
	for _, kind := range []string{"parent", "orphan-parent"} {
		t.Run(kind, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "owned-child")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := Command(ctx, os.Args[0], "-test.run=^TestOwnedProcessHelper$")
			cmd.Env = append(os.Environ(), "KTEST_CORE_PROCESS_HELPER="+kind, "KTEST_CORE_PROCESS_FILE="+pidFile)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			done := make(chan error, 1)
			go func() { done <- Run(cmd) }()
			var port int
			deadline := time.Now().Add(10 * time.Second)
			for port == 0 {
				if fields := strings.Fields(readHelperFile(pidFile)); len(fields) == 2 {
					pid, _ := strconv.Atoi(fields[0])
					port, _ = strconv.Atoi(fields[1])
					t.Cleanup(func() {
						if child, err := os.FindProcess(pid); err == nil {
							_ = child.Kill()
						}
					})
				}
				if time.Now().After(deadline) {
					t.Fatal("owned child did not publish its listener")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if kind == "parent" {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("core Wait did not finish")
			}
			deadline = time.Now().Add(3 * time.Second)
			for {
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
				if err != nil {
					break
				}
				_ = conn.Close()
				if time.Now().After(deadline) {
					t.Fatal("owned carrier child survived its parent")
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

func readHelperFile(path string) string { raw, _ := os.ReadFile(path); return string(raw) }
