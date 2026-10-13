package proofserver

import (
	"encoding/hex"
	"net/http"
)

// Handler is a deliberately narrow dynamic proof endpoint. Expose it via an
// HTTPS reverse proxy for remote tests. The service does not forward traffic.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__ktest/proof", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		token := r.Header.Get("X-Ktest-Challenge")
		if len(token) != 32 {
			http.Error(w, "invalid challenge", http.StatusBadRequest)
			return
		}
		if b, err := hex.DecodeString(token); err != nil || len(b) != 16 {
			http.Error(w, "invalid challenge", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Ktest-Proof", token)
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
