package main

import (
	"context"
	"errors"
	"os"
	"os/signal"

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
		Use:   "wrap [--policy file] -- <cmd> [args...]",
		Short: "Run an MCP server behind the firewall (stdio)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return proxy.Wrap(cmd.Context(), args, nil, cmd.InOrStdin(), cmd.OutOrStdout(), proxy.Hooks{})
		},
	}
	wrap.Flags().String("policy", "", "policy file")

	proxy := stub(&cobra.Command{
		Use:   "proxy --upstream URL",
		Short: "Run the firewall in front of an HTTP MCP server",
	})
	proxy.Flags().String("upstream", "", "upstream MCP server URL")

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

	logCmd := stub(&cobra.Command{
		Use:   "log",
		Short: "Pretty-print the audit log",
	})
	logCmd.Flags().Bool("tail", false, "follow the log")

	root.AddCommand(
		stub(&cobra.Command{
			Use:   "init",
			Short: "Write the default policy and detect Claude Code / Cursor config",
		}),
		wrap,
		proxy,
		secret,
		approve,
		stub(&cobra.Command{
			Use:   "verify",
			Short: "Check the audit log hash chain",
		}),
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
