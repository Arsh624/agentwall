package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/spf13/cobra"
)

// runInit writes the default policy (never over an existing one) and prints how
// to put the user's MCP servers behind agentwall. It does not edit their configs.
func runInit(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	path := filepath.Join(stateDir(), "policy.yaml")
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(stateDir(), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, policy.DefaultYAML(), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "Wrote the default policy to %s\n", path)
	} else if err != nil {
		return err
	} else {
		fmt.Fprintf(out, "Policy already exists at %s (left unchanged)\n", path)
	}

	home, _ := os.UserHomeDir()
	found := false
	for _, config := range []string{".mcp.json", filepath.Join(".cursor", "mcp.json"),
		filepath.Join(home, ".claude.json"), filepath.Join(home, ".cursor", "mcp.json")} {
		found = showWrapped(cmd, config) || found
	}
	if !found {
		fmt.Fprint(out, `
No MCP config found here or in your home directory. In .mcp.json (Claude Code) or
.cursor/mcp.json (Cursor), start each server through agentwall, for example:

  "github": {
    "command": "agentwall",
    "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
  }
`)
	}
	return nil
}

// showWrapped prints the agentwall version of every server in one MCP config file.
func showWrapped(cmd *cobra.Command, config string) bool {
	raw, err := os.ReadFile(config)
	if err != nil {
		return false
	}
	var doc struct {
		Servers map[string]map[string]any `json:"mcpServers"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.Servers) == 0 {
		return false
	}
	out := cmd.OutOrStdout()
	names := make([]string, 0, len(doc.Servers))
	for name := range doc.Servers {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Fprintf(out, "\nFound %s. Change these entries to put the servers behind agentwall:\n", config)
	for _, name := range names {
		server := doc.Servers[name]
		command, _ := server["command"].(string)
		switch url, _ := server["url"].(string); {
		case url != "":
			fmt.Fprintf(out, "\n  %q is an HTTP server: run `agentwall proxy --upstream %s --server %s`\n  and point its \"url\" at the address that command prints.\n", name, url, name)
			continue
		case command == "" || strings.HasPrefix(filepath.Base(command), "agentwall"):
			continue // nothing to wrap, or already wrapped
		}
		args := []string{"wrap", "--server", name, "--", command}
		for _, a := range toStrings(server["args"]) {
			args = append(args, a)
		}
		quoted := make([]string, len(args))
		for i, a := range args {
			b, _ := json.Marshal(a)
			quoted[i] = string(b)
		}
		fmt.Fprintf(out, "\n  %q: {\n    \"command\": \"agentwall\",\n    \"args\": [%s]\n  }\n", name, strings.Join(quoted, ", "))
		if env, _ := server["env"].(map[string]any); len(env) > 0 {
			vars := make([]string, 0, len(env))
			for v := range env {
				vars = append(vars, v)
			}
			sort.Strings(vars)
			fmt.Fprintf(out, "  Its \"env\" sets %s. If these are secrets, take them out of the config:\n"+
				"  run `agentwall secret set <name>` and add to the policy:\n"+
				"    servers: {%s: {env: {%s: \"vault:<name>\"}}}\n", strings.Join(vars, ", "), name, vars[0])
		}
	}
	return true
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
