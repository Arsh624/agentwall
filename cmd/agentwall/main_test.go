package main

import (
	"io"
	"strings"
	"testing"
)

func TestSubcommandsRegistered(t *testing.T) {
	cases := []string{
		"init",
		"wrap -- echo",
		"proxy",
		"secret set NAME",
		"approve srv/tool",
		"verify",
		"attack",
		"log",
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			cmd := newRootCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(strings.Fields(line))
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("%q: expected error, got nil", line)
			}
			if err.Error() != "not implemented" {
				t.Fatalf("%q: error = %q, want %q", line, err.Error(), "not implemented")
			}
		})
	}
}
