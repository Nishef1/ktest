package coreprocess

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

// Run starts cmd, registers it until it exits and waits for it. A core
// whose pipes are held open by a surviving child cannot block Wait forever.
func Run(cmd *exec.Cmd) error {
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 3 * time.Second
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	// Windows Job Objects ensure Psiphon/Tor descendants die even if Aether
	// exits first. Untracked descendants must never outlive this session.
	closeJob, err := confineTrackedProcess(cmd.Process)
	if err != nil {
		KillTree(pid)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	defer closeJob()
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

// Reap ends the process tree of every core still registered and
// reports how many it had to kill.
func Reap() int {
	liveProcs.mu.Lock()
	pids := make([]int, 0, len(liveProcs.procs))
	for pid := range liveProcs.procs {
		pids = append(pids, pid)
	}
	liveProcs.mu.Unlock()
	for _, pid := range pids {
		KillTree(pid)
	}
	return len(pids)
}

// Count is the number of cores currently registered.
func Count() int {
	liveProcs.mu.Lock()
	defer liveProcs.mu.Unlock()
	return len(liveProcs.procs)
}

// WaitGone waits until no registered core remains, up to limit.
func WaitGone(ctx context.Context, limit time.Duration) bool {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for Count() > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return Count() == 0
		case <-tick.C:
		}
	}
	return true
}
