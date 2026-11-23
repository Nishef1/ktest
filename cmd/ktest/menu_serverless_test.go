package main

import "testing"

func TestServerlessListedBesidePsiphon(t *testing.T) {
	psiphon, ok := findItem("6")
	if !ok || psiphon.mode != ModePsiphon {
		t.Fatal("Psiphon mode disappeared")
	}
	serverless, ok := findItem("7")
	if !ok || serverless.name != "Serverless" || serverless.action == nil {
		t.Fatalf("Serverless selector missing: %+v", serverless)
	}
	if len(serverlessVariants) != 3 || serverlessVariants[2].variant != "OOB" {
		t.Fatal("missing Fragment A, B or OOB")
	}
}
