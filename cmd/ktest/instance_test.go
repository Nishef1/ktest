package main

import (
	"errors"
	"testing"
)

func TestSecondConnectionSessionIsRefused(t *testing.T) {
	release, err := claimSession()
	if err != nil {
		t.Skip("another ktest connection is running on this machine")
	}
	if _, err := claimSession(); !errors.Is(err, errAnotherSession) {
		release()
		t.Fatalf("second session was not refused: %v", err)
	}
	release()
	again, err := claimSession()
	if err != nil {
		t.Fatalf("session lock was not released: %v", err)
	}
	again()
}
