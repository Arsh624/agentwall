package main

import (
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	out, err := run(t, "", "--version")
	if err != nil || !strings.Contains(out, "agentwall version dev") {
		t.Fatalf("--version: %q, %v", out, err)
	}
}
