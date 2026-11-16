package proxy

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Wrap starts the upstream MCP server argv with env (nil inherits ours) and
// proxies the agent to its stdio. It returns when the server exits.
func Wrap(ctx context.Context, argv, env []string, agentIn io.Reader, agentOut io.Writer, h Hooks) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stderr = os.Stderr // stdout is the protocol channel, so logs stay on stderr
	upIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upstream server: %w", err)
	}
	if err := Run(agentIn, agentOut, upIn, upOut, h); err != nil {
		cmd.Process.Kill() // we can no longer reach the agent; don't leave the server running
		cmd.Wait()
		return err
	}
	return cmd.Wait()
}
