//go:build windows

package coreprocess

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows does not have Unix process groups. A kill-on-close Job Object is
// scoped to the exact child handle, rather than every process named "aether".
// Closing the job also terminates descendants that outlived their parent.
func confineTrackedProcess(proc *os.Process) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create process job: %w", err)
	}
	closeJob := func() { _ = windows.CloseHandle(job) }
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		closeJob()
		return nil, fmt.Errorf("set process-job cleanup policy: %w", err)
	}
	var attachErr error
	err = proc.WithHandle(func(handle uintptr) {
		attachErr = windows.AssignProcessToJobObject(job, windows.Handle(handle))
	})
	if err != nil || attachErr != nil {
		closeJob()
		return nil, fmt.Errorf("attach helper process to cleanup job: %v / %v", err, attachErr)
	}
	return closeJob, nil
}
