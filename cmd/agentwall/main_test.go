package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/agentwall/agentwall/internal/mockserver"
)

func TestMain(m *testing.M) {
	mockserver.RunIfChild() // lets "wrap" run this test binary as its upstream server
	os.Exit(m.Run())
}

func TestStubCommandsRegistered(t *testing.T) {
	cases := []string{
		"init",
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

func TestWrapProxiesToUpstream(t *testing.T) {
	t.Setenv(mockserver.EnvScenario, "../../testdata/basic.json")
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"))
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"wrap", "--", os.Args[0]})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"read_file"`) || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout must hold exactly the upstream's reply, got %q", out.String())
	}
}

func TestWrapNeedsACommand(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"wrap"})
	if err := cmd.Execute(); err == nil || err.Error() == "not implemented" {
		t.Fatalf("wrap without a command should be a usage error, got %v", err)
	}
}
