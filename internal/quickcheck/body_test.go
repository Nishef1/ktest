package quickcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTruncatedProbeBodyIsNotGreen(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	defer server.Close()
	out := checkTarget(context.Background(), server.Client(), Target{Name: "body", URL: server.URL, Method: http.MethodGet})
	if out.Success || !out.Reachable {
		t.Fatalf("truncated body reported as opened: %+v", out)
	}
}
