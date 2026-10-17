//go:build !windows

package main

import "os"

// On Unix, configureEnrollmentProcess places the child in its own process
// group and its cancellation path kills that group.
func confineTrackedProcess(_ *os.Process) (func(), error) {
	return func() {}, nil
}
