//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func hideConsole(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} }

// Layout of JOBOBJECT_EXTENDED_LIMIT_INFORMATION (winnt.h).
type jobIOCounters struct{ a, b, c, d, e, f uint64 }

type jobBasicLimits struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimits struct {
	Basic                 jobBasicLimits
	IO                    jobIOCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// job is kept open for the life of the process: when ktest ends for any reason
// (including its console window being closed or the process being killed),
// Windows closes the handle and kills every core still running in the job.
var job syscall.Handle

// killChildrenOnExit puts ktest into a kill-on-close job object. Child
// processes started afterwards (Xray, ByeDPI, sing-box) inherit the job, so a
// crash can no longer leave orphaned cores holding the local ports.
func killChildrenOnExit() {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	create := kernel.NewProc("CreateJobObjectW")
	setInfo := kernel.NewProc("SetInformationJobObject")
	assign := kernel.NewProc("AssignProcessToJobObject")
	h, _, _ := create.Call(0, 0)
	if h == 0 {
		return
	}
	const (
		jobObjectExtendedLimitInformation = 9
		killOnJobClose                    = 0x2000
	)
	var info jobExtendedLimits
	info.Basic.LimitFlags = killOnJobClose
	if r, _, _ := setInfo.Call(h, jobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		_ = syscall.CloseHandle(syscall.Handle(h))
		return
	}
	self, _ := syscall.GetCurrentProcess()
	if r, _, _ := assign.Call(h, uintptr(self)); r == 0 {
		_ = syscall.CloseHandle(syscall.Handle(h))
		return
	}
	job = syscall.Handle(h)
}
