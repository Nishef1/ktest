package mobilebridge

import (
	"testing"

	"github.com/Nishef1/ktest/internal/edges"
)

func TestRankFastestFirst(t *testing.T) {
	got := rankFastestFirst([]edges.ScanResult{
		{IP: "1.1.1.3", ElapsedMS: 300}, {IP: "1.1.1.1", ElapsedMS: 80}, {IP: "1.1.1.2", ElapsedMS: 120},
	})
	if got[0].IP != "1.1.1.1" || got[1].IP != "1.1.1.2" || got[2].IP != "1.1.1.3" {
		t.Fatalf("order = %+v", got)
	}
}
