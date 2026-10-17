package main

import (
    "context"

    "github.com/Nishef1/ktest/internal/egresscheck"
)

// The CLI and Android now share the same Go TLS-protected exit verification.
func probeForeignExit(parent context.Context, socks string) (string, string, error) {
    return egresscheck.ProbeForeignExit(parent, socks)
}

func probeExitLocation(parent context.Context, socks string) (string, string, error) {
    return egresscheck.ProbeExitLocation(parent, socks)
}

func parseForeignTrace(body string) (string, string, error) {
    return egresscheck.ParseForeignTrace(body)
}

func parseExitTrace(body string) (string, string, error) {
    return egresscheck.ParseExitTrace(body)
}
