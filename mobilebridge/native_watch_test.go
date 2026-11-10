package mobilebridge

import (
	"testing"
	"time"
)

func TestNativeStalled(t *testing.T) {
	now := time.Now()
	s, r := 20*time.Second, time.Minute
	cases := []struct {
		name     string
		up, down time.Time
		want     bool
	}{
		{"idle", time.Time{}, time.Time{}, false},
		{"old traffic", now.Add(-5 * time.Minute), time.Time{}, false},
		{"sent, never answered", now.Add(-5 * time.Second), time.Time{}, true},
		{"sent, answers keep pace", now.Add(-2 * time.Second), now.Add(-3 * time.Second), false},
		{"sent, answer long ago", now.Add(-2 * time.Second), now.Add(-40 * time.Second), true},
	}
	for _, c := range cases {
		if got := nativeStalled(c.up, c.down, now, s, r); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
