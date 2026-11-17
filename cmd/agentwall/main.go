package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
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

// version is set by the release build with -ldflags "-X main.version=..."
var version = "dev"

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
		Version:      version,
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

	proxyCmd := &cobra.Command{
		Use:   "proxy --upstream URL [--listen addr] [--server name] [--policy file]",
		Short: "Run the firewall in front of an HTTP MCP server",
		Args:  cobra.NoArgs,
		RunE:  runProxy,
	}
	proxyCmd.Flags().String("upstream", "", "upstream MCP server URL")
	proxyCmd.Flags().String("listen", "127.0.0.1:7878", "address the agent connects to")
	proxyCmd.Flags().String("policy", "", "policy file (default: policy.yaml in the state dir, else the built-in policy)")
	proxyCmd.Flags().String("server", "", "name the policy knows this server by (default: the upstream's host name)")

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
		&cobra.Command{
			Use:   "init",
			Short: "Write the default policy and show how to wrap your Claude Code / Cursor servers",
			Args:  cobra.NoArgs,
			RunE:  runInit,
		},
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

// resolve turns name → vault secret name into name → secret value.
func resolve(refs, secrets map[string]string) (map[string]string, error) {
	values := map[string]string{}
	for name, secret := range refs {
		value, ok := secrets[secret]
		if !ok {
			return nil, fmt.Errorf("secret %q is not in the vault; run: agentwall secret set %s", secret, secret)
		}
		values[name] = value
	}
	return values, nil
}

// guard opens the firewall for one server and resolves the credentials the
// policy gives it: environment variables (stdio) and HTTP headers.
func guard(cmd *cobra.Command, server string) (fw *firewall.Firewall, env, headers map[string]string, err error) {
	policyFlag, _ := cmd.Flags().GetString("policy")
	pol, err := loadPolicy(policyFlag)
	if err != nil {
		return nil, nil, nil, err
	}
	secrets, err := vault.Open(stateDir()).All()
	if err != nil {
		if len(pol.Env(server))+len(pol.Headers(server)) > 0 {
			return nil, nil, nil, fmt.Errorf("opening the vault: %w", err)
		}
		// no keychain here and nothing to inject: go on with pattern-only redaction
		fmt.Fprintf(cmd.ErrOrStderr(), "agentwall: vault unavailable, redacting known token formats only: %v\n", err)
	}
	if env, err = resolve(pol.Env(server), secrets); err != nil {
		return nil, nil, nil, err
	}
	if headers, err = resolve(pol.Headers(server), secrets); err != nil {
		return nil, nil, nil, err
	}
	fw, err = firewall.Open(firewall.Config{StateDir: stateDir(), Server: server, Session: sessionID(),
		Policy: pol, Secrets: secrets, Ask: firewall.TerminalAsk})
	return fw, env, headers, err
}

func runWrap(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	if server == "" {
		server = serverName(args)
	}
	fw, secretEnv, _, err := guard(cmd, server)
	if err != nil {
		return err
	}
	defer fw.Close()
	// the server gets our environment plus its vault secrets, minus the vault passphrase
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, vault.PassphraseEnv+"=") {
			env = append(env, kv)
		}
	}
	for name, value := range secretEnv {
		env = append(env, name+"="+value)
	}
	return proxy.Wrap(cmd.Context(), args, env, cmd.InOrStdin(), cmd.OutOrStdout(), fw.Hooks())
}

func runProxy(cmd *cobra.Command, _ []string) error {
	upstream, _ := cmd.Flags().GetString("upstream")
	u, err := url.Parse(upstream)
	if upstream == "" || err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("--upstream must be the http(s) URL of the MCP server, got %q", upstream)
	}
	server, _ := cmd.Flags().GetString("server")
	if server == "" {
		server = u.Hostname()
	}
	fw, _, headers, err := guard(cmd, server)
	if err != nil {
		return err
	}
	defer fw.Close()

	listen, _ := cmd.Flags().GetString("listen")
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok && !tcp.IP.IsLoopback() {
		fmt.Fprintln(cmd.ErrOrStderr(), "agentwall: warning: listening beyond this machine; anyone who can reach this port can use the server's credentials")
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "agentwall: firewall for %s (policy name %q) is on http://%s\n", upstream, server, ln.Addr())
	// shortcut: every client of this process shares one session; key taint by Mcp-Session-Id if several agents share a proxy.
	srv := &http.Server{Handler: proxy.HTTPHandler(upstream, headers, fw.Hooks()), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-cmd.Context().Done()
		srv.Close()
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
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
