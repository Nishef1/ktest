package mobilebridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestServerlessMethodCatalogAndUnknownSelection(t *testing.T) {
	var catalog struct {
		Methods []struct {
			ID string `json:"id"`
		} `json:"methods"`
	}
	if err := json.Unmarshal([]byte(ServerlessMethodCatalog()), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Methods) != 3 || catalog.Methods[0].ID != "A" ||
		catalog.Methods[1].ID != "B" || catalog.Methods[2].ID != "OOB" {
		t.Fatalf("invalid serverless methods: %+v", catalog.Methods)
	}
	if _, err := StartAndroidServerlessProxy("unknown", "/tmp/native", "/tmp/private"); err == nil ||
		!strings.Contains(err.Error(), "method") {
		t.Fatalf("unknown serverless method should be rejected: %v", err)
	}
}
