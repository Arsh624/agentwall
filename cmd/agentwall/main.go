package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arsh624/agentwall/attacks"
	"github.com/Arsh624/agentwall/internal/attack"
	"github.com/Arsh624/agentwall/internal/audit"
	"github.com/Arsh624/agentwall/internal/firewall"
	"github.com/Arsh624/agentwall/internal/mockserver"
	"github.com/Arsh624/agentwall/internal/pin"
	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/Arsh624/agentwall/internal/proxy"
	"github.com/Arsh624/agentwall/internal/vault"
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
	secret.AddCommand(
		&cobra.Command{
			Use:   "set NAME",
			Short: "Store a secret in the vault (the value is read from stdin)",
			Args:  cobra.ExactArgs(1),
			RunE:  runSecretSet,
		},
		&cobra.Command{
			Use:   "list",
			Short: "List the names of the stored secrets",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				names, err := vault.Open(stateDir()).List()
				for _, n := range names {
					fmt.Fprintln(cmd.OutOrStdout(), n)
				}
				return err
			},
		},
	)

	approve := &cobra.Command{
		Use:   "approve <server>/<tool>",
		Short: "Accept a changed tool",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, tool, ok := strings.Cut(args[0], "/")
			if !ok || server == "" || tool == "" {
				return fmt.Errorf("want <server>/<tool>, got %q", args[0])
			}
			if err := pin.Open(pinsDir()).Approve(server, tool); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "approved %s/%s: the agent sees it again after it next lists tools\n", server, tool)
			return nil
		},
	}

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
		&cobra.Command{
			Use:   "attack",
			Short: "Run the attack suite and print the score",
			Args:  cobra.NoArgs,
			RunE:  runAttack,
		},
		logCmd,
		&cobra.Command{
			Use:    "mock-server <scenario.json>",
			Short:  "Run a scripted mock MCP server on stdio (for benchmarks)",
			Hidden: true,
			Args:   cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				sc, err := mockserver.Load(args[0])
				if err != nil {
					return err
				}
				return mockserver.Serve(cmd.InOrStdin(), cmd.OutOrStdout(), sc)
			},
		},
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

func auditPath() string { return firewall.AuditPath(stateDir()) }
func pinsDir() string   { return firewall.PinsDir(stateDir()) }

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

func runSecretSet(cmd *cobra.Command, args []string) error {
	// shortcut: the value echoes when typed at a terminal (hiding it needs x/term); pipe it in to avoid that.
	if f, ok := cmd.InOrStdin().(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "Value for %s (input is visible): ", args[0])
		}
	}
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	value := strings.TrimRight(line, "\r\n")
	if err := vault.Open(stateDir()).Set(args[0], value); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "stored %s\n", args[0])
	if len(value) < 8 {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: values under 8 characters are not redacted from tool output")
	}
	return nil
}

// upstreamEnv is our environment plus the server's vault secrets, minus the vault passphrase.
func upstreamEnv(refs, secrets map[string]string) ([]string, error) {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, vault.PassphraseEnv+"=") {
			env = append(env, kv)
		}
	}
	for name, secret := range refs {
		value, ok := secrets[secret]
		if !ok {
			return nil, fmt.Errorf("secret %q is not in the vault; run: agentwall secret set %s", secret, secret)
		}
		env = append(env, name+"="+value)
	}
	return env, nil
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
	secrets, err := vault.Open(stateDir()).All()
	if err != nil {
		if len(pol.Env(server)) > 0 {
			return fmt.Errorf("opening the vault: %w", err)
		}
		// no keychain here and nothing to inject: go on with pattern-only redaction
		fmt.Fprintf(cmd.ErrOrStderr(), "agentwall: vault unavailable, redacting known token formats only: %v\n", err)
	}
	env, err := upstreamEnv(pol.Env(server), secrets)
	if err != nil {
		return err
	}
	fw, err := firewall.Open(firewall.Config{StateDir: stateDir(), Server: server, Session: sessionID(),
		Policy: pol, Secrets: secrets, Ask: firewall.TerminalAsk})
	if err != nil {
		return err
	}
	defer fw.Close()
	return proxy.Wrap(cmd.Context(), args, env, cmd.InOrStdin(), cmd.OutOrStdout(), fw.Hooks())
}

func runAttack(cmd *cobra.Command, _ []string) error {
	log.SetOutput(io.Discard) // the firewall's warnings would clutter the table
	scs, err := attack.Load(attacks.FS)
	if err != nil {
		return err
	}
	var results []attack.Result
	for _, sc := range scs {
		r, err := attack.Run(sc)
		if err != nil {
			return fmt.Errorf("%s: %w", sc.Name, err)
		}
		results = append(results, r)
	}
	if !attack.Report(cmd.OutOrStdout(), results) {
		return errors.New("the attack suite found a gap")
	}
	return nil
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
