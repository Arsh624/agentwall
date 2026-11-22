package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// serverSet is one mcpServers map inside an agent config file.
type serverSet struct {
	file  string
	where string   // shown to the user: "" for the top-level map, else e.g. `projects["C:\work"]`
	path  []string // keys from the document root to the map
}

// serverSets lists the MCP server maps of Claude Code and Cursor that apply here:
// the project files in the current directory, the user files in home, and in
// ~/.claude.json the user-scope servers and the current project's local servers.
func serverSets() []serverSet {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	sets := []serverSet{
		{file: ".mcp.json", path: []string{"mcpServers"}},
		{file: filepath.Join(".cursor", "mcp.json"), path: []string{"mcpServers"}},
		{file: filepath.Join(home, ".claude.json"), path: []string{"mcpServers"}},
		{file: filepath.Join(home, ".cursor", "mcp.json"), path: []string{"mcpServers"}},
	}
	claude := filepath.Join(home, ".claude.json")
	if doc, err := readConfig(claude); err == nil {
		projects, _ := doc["projects"].(map[string]any)
		for key := range projects {
			if samePath(key, cwd) {
				sets = append(sets, serverSet{file: claude, where: fmt.Sprintf("projects[%q]", key), path: []string{"projects", key, "mcpServers"}})
			}
		}
	}
	return sets
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(filepath.FromSlash(a)), filepath.Clean(filepath.FromSlash(b))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func readConfig(file string) (map[string]any, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exactly as written
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return doc, nil
}

// servers returns the map at set.path in doc (nil if there is none).
func (set serverSet) servers(doc map[string]any) map[string]any {
	var v any = doc
	for _, k := range set.path {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	m, _ := v.(map[string]any)
	return m
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// isWrapped says whether a stdio server already starts through agentwall.
func isWrapped(server map[string]any) bool {
	command, _ := server["command"].(string)
	base := command[strings.LastIndexAny(command, `/\`)+1:] // either separator: configs travel between systems
	return strings.HasPrefix(strings.ToLower(base), "agentwall")
}

// wrapArgs is the argument list that runs command args... behind agentwall.
func wrapArgs(name string, server map[string]any) []any {
	command, _ := server["command"].(string)
	args := []any{"wrap", "--server", name, "--", command}
	for _, a := range toStrings(server["args"]) {
		args = append(args, a)
	}
	return args
}

// checkConfigs prints one line per MCP server that does not go through agentwall,
// and nothing when every server does.
func checkConfigs(out io.Writer) {
	for _, set := range serverSets() {
		doc, err := readConfig(set.file)
		if err != nil {
			continue
		}
		servers := set.servers(doc)
		for _, name := range sortedKeys(servers) {
			server, _ := servers[name].(map[string]any)
			url, _ := server["url"].(string)
			switch {
			case url != "":
				fmt.Fprintf(out, "agentwall: %q in %s%s is an HTTP server that does not go through agentwall: run `agentwall proxy --upstream %s --server %s` and point its url there\n",
					name, set.file, suffix(set.where), url, name)
			case server["command"] != nil && !isWrapped(server):
				fmt.Fprintf(out, "agentwall: %q in %s%s is not protected by agentwall: run `agentwall init --apply` (or /agentwall:setup in Claude Code)\n",
					name, set.file, suffix(set.where))
			}
		}
	}
}

func suffix(where string) string {
	if where == "" {
		return ""
	}
	return " " + where
}

// applyConfigs rewrites every stdio server in the agent configs to start through
// agentwall (by its absolute path), after backing each changed file up.
func applyConfigs(out io.Writer) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding agentwall's own path: %w", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	byFile := map[string][]serverSet{}
	var files []string
	for _, set := range serverSets() {
		if _, ok := byFile[set.file]; !ok {
			files = append(files, set.file)
		}
		byFile[set.file] = append(byFile[set.file], set)
	}
	changed := 0
	for _, file := range files {
		doc, err := readConfig(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		var wrapped []string
		for _, set := range byFile[file] {
			servers := set.servers(doc)
			for _, name := range sortedKeys(servers) {
				server, _ := servers[name].(map[string]any)
				if url, _ := server["url"].(string); url != "" {
					fmt.Fprintf(out, "  %q in %s is an HTTP server: run `agentwall proxy --upstream %s --server %s` and point its url at the address it prints\n", name, file, url, name)
					continue
				}
				if command, _ := server["command"].(string); command == "" || isWrapped(server) {
					continue
				}
				server["args"] = wrapArgs(name, server)
				server["command"] = exe
				wrapped = append(wrapped, name+suffix(set.where))
			}
		}
		if len(wrapped) == 0 {
			continue
		}
		backup, err := rewrite(file, doc)
		if err != nil {
			return err
		}
		changed++
		fmt.Fprintf(out, "Put %s behind agentwall in %s\n  backup: %s (to undo, copy it back over the file)\n", strings.Join(wrapped, ", "), file, backup)
	}
	if changed == 0 {
		fmt.Fprintln(out, "Every MCP server found already goes through agentwall (or there are none here).")
		return nil
	}
	fmt.Fprintln(out, "Restart your agent (Claude Code, Cursor) so it starts the servers through agentwall.")
	return nil
}

// rewrite backs file up, then replaces it with doc through a temp file and a rename.
func rewrite(file string, doc map[string]any) (backup string, err error) {
	orig, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(file)
	if err != nil {
		return "", err
	}
	backup = file + ".agentwall-backup-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.WriteFile(backup, orig, info.Mode().Perm()); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".agentwall-*")
	if err != nil {
		return "", err
	}
	_, err = tmp.Write(buf.Bytes())
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), info.Mode().Perm())
	}
	if err == nil {
		err = os.Rename(tmp.Name(), file)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return backup, nil
}
