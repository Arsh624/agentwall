package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentwall/agentwall/internal/audit"
	"github.com/agentwall/agentwall/internal/firewall"
	"github.com/agentwall/agentwall/internal/policy"
	"github.com/agentwall/agentwall/internal/proxy"
	"github.com/spf13/cobra"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:          "agentwall",
		SilenceUsage: true,
	}

	wrap := &cobra.Command{
		Use:   "wrap [--policy file] [--server name] -- <cmd> [args...]",
		Short: "Run an MCP server behind the firewall (stdio)",
		Args:  cobra.MinimumNArgs(1),
		RunE:  runWrap,
	}
	wrap.Flags().String("policy", "", "policy file (default: policy.yaml in the state dir, else the built-in policy)")
	wrap.Flags().String("server", "", "name the policy knows this server by (default: guessed from the command)")

	proxyCmd := stub(&cobra.Command{
		Use:   "proxy --upstream URL",
		Short: "Run the firewall in front of an HTTP MCP server",
	})
	proxyCmd.Flags().String("upstream", "", "upstream MCP server URL")

	secret := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets in the vault",
	}
	secret.AddCommand(stub(&cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret in the vault",
		Args:  cobra.ExactArgs(1),
	}))

	approve := stub(&cobra.Command{
		Use:   "approve <server>/<tool>",
		Short: "Accept a changed tool",
		Args:  cobra.ExactArgs(1),
	})

	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Pretty-print the audit log",
		RunE:  runLog,
	}
	logCmd.Flags().Bool("tail", false, "keep printing new entries")

	root.AddCommand(
		stub(&cobra.Command{
			Use:   "init",
			Short: "Write the default policy and detect Claude Code / Cursor config",
		}),
		wrap,
		proxyCmd,
		secret,
		approve,
		&cobra.Command{
			Use:   "verify",
			Short: "Check the audit log hash chain",
			RunE: func(cmd *cobra.Command, _ []string) error {
				n, err := audit.Verify(auditPath())
				if err != nil {
					return fmt.Errorf("audit log has been tampered with or is damaged: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "audit log OK: %d entries\n", n)
				return nil
			},
		},
		stub(&cobra.Command{
			Use:   "attack",
			Short: "Run the attack suite and print the score",
		}),
		logCmd,
	)
	return root
}

func stub(c *cobra.Command) *cobra.Command {
	c.RunE = func(*cobra.Command, []string) error {
		return errors.New("not implemented")
	}
	return c
}

// stateDir is ~/.agentwall, or $AGENTWALL_HOME.
func stateDir() string {
	if d := os.Getenv("AGENTWALL_HOME"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agentwall"
	}
	return filepath.Join(home, ".agentwall")
}

func auditPath() string { return filepath.Join(stateDir(), "audit.jsonl") }

func loadPolicy(flag string) (*policy.Policy, error) {
	if flag != "" {
		return policy.Load(flag)
	}
	p, err := policy.Load(filepath.Join(stateDir(), "policy.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return policy.Default(), nil
	}
	return p, err
}

// serverName guesses the policy name of a wrapped server: the text after
// "server-" in its command ("@modelcontextprotocol/server-github" → "github"),
// else the program's base name.
func serverName(argv []string) string {
	for _, a := range argv {
		if _, name, ok := strings.Cut(a, "server-"); ok {
			name, _, _ = strings.Cut(name, "@") // drop a pinned npm version
			return name
		}
	}
	base := path.Base(strings.ReplaceAll(argv[0], `\`, "/"))
	return strings.TrimSuffix(base, path.Ext(base))
}

// sessionID is shared by every agentwall the same agent started: they have the same parent.
func sessionID() string {
	if s := os.Getenv("AGENTWALL_SESSION"); s != "" {
		return s
	}
	return fmt.Sprintf("ppid-%d", os.Getppid())
}

func runWrap(cmd *cobra.Command, args []string) error {
	policyFlag, _ := cmd.Flags().GetString("policy")
	pol, err := loadPolicy(policyFlag)
	if err != nil {
		return err
	}
	server, _ := cmd.Flags().GetString("server")
	if server == "" {
		server = serverName(args)
	}
	log, err := audit.Open(auditPath())
	if err != nil {
		return err
	}
	defer log.Close()
	fw := &firewall.Firewall{Server: server, Session: sessionID(), Policy: pol, Audit: log, Ask: firewall.TerminalAsk}
	return proxy.Wrap(cmd.Context(), args, nil, cmd.InOrStdin(), cmd.OutOrStdout(), fw.Hooks())
}

func runLog(cmd *cobra.Command, _ []string) error {
	tail, _ := cmd.Flags().GetBool("tail")
	printed := 0
	for {
		// shortcut: --tail re-reads the whole file every half second; seek from the last offset if logs get big.
		entries, err := audit.Read(auditPath())
		if err != nil {
			return err
		}
		for _, e := range entries[printed:] {
			fmt.Fprintf(cmd.OutOrStdout(), "%s  %-5s  %s/%s  %s\n", e.TS, e.Decision, e.Server, e.Tool, e.Reason)
		}
		printed = len(entries)
		if !tail {
			return nil
		}
		select {
		case <-cmd.Context().Done():
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
}
