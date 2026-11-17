//go:build !windows

package main

import "os"

// agentPID is the process that started us. A `sh -c` wrapper execs its last
// command, so the parent is the agent itself.
func agentPID() int { return os.Getppid() }
