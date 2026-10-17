package main

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// Every core ktest starts is registered here, so leaving a session or the
// program can end whatever is still alive (a core that ignored its context,
// or a grandchild such as Aether's Psiphon helper) instead of leaving it to
// hold a port or CPU.
var liveProcs = struct {
	mu    sync.Mutex
	procs map[int]*exec.Cmd
}{procs: map[int]*exec.Cmd{}}

// runTracked starts cmd, registers it until it exits and waits for it. A core
// whose pipes are held open by a surviving child cannot block Wait forever.
func runTracked(cmd *exec.Cmd) error {
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 3 * time.Second
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	liveProcs.mu.Lock()
	liveProcs.procs[pid] = cmd
	liveProcs.mu.Unlock()
	defer func() {
		liveProcs.mu.Lock()
		delete(liveProcs.procs, pid)
		liveProcs.mu.Unlock()
	}()
	return cmd.Wait()
}

// reapTracked ends the process tree of every core still registered and
// reports how many it had to kill.
func reapTracked() int {
	liveProcs.mu.Lock()
	pids := make([]int, 0, len(liveProcs.procs))
	for pid := range liveProcs.procs {
		pids = append(pids, pid)
	}
	liveProcs.mu.Unlock()
	for _, pid := range pids {
		killProcessTree(pid)
	}
	return len(pids)
}

// trackedCount is the number of cores currently registered.
func trackedCount() int {
	liveProcs.mu.Lock()
	defer liveProcs.mu.Unlock()
	return len(liveProcs.procs)
}

// waitTrackedGone waits until no registered core remains, up to limit.
func waitTrackedGone(ctx context.Context, limit time.Duration) bool {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for trackedCount() > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return trackedCount() == 0
		case <-tick.C:
		}
	}
	return true
}
