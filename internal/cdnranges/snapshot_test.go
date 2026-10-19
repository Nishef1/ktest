package cdnranges

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
)

// KTEST_UPDATE_CDN_SNAPSHOT=1 go test ./internal/cdnranges -run Snapshot
// refreshes the embedded inventory from the providers' live sources.
func TestUpdateEmbeddedSnapshot(t *testing.T) {
	if os.Getenv("KTEST_UPDATE_CDN_SNAPSHOT") == "" {
		t.Skip("set KTEST_UPDATE_CDN_SNAPSHOT=1 to refresh snapshot.json")
	}
	set := &Set{Version: 1, Providers: map[string]*Range{}}
	client := &http.Client{Timeout: 60 * time.Second}
	for _, p := range Providers {
		r, err := fetchProvider(context.Background(), client, p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		t.Logf("%s: %d v4, %d v6 from %s", p, len(r.V4), len(r.V6), r.Source)
		set.Providers[p] = r
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("snapshot.json", raw, 0644); err != nil {
		t.Fatal(err)
	}
}
