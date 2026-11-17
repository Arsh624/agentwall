package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Started through cmd /c (as many Windows MCP configs do), agentwall must
// still find the agent: here, the test process.
func TestAgentPIDLooksPastCmd(t *testing.T) {
	cmd := exec.Command("cmd", "/c", os.Args[0], "-test.run=^TestHelperAgentPID$")
	cmd.Env = append(os.Environ(), "AGENTWALL_HELPER_PID=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got, _ := strconv.Atoi(strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]))
	if got != os.Getpid() {
		t.Fatalf("agentPID under cmd /c = %d, want the test process %d (output %q)", got, os.Getpid(), out)
	}
}

func TestHelperAgentPID(t *testing.T) {
	if os.Getenv("AGENTWALL_HELPER_PID") == "" {
		t.Skip("helper for TestAgentPIDLooksPastCmd")
	}
	fmt.Println(agentPID())
}
