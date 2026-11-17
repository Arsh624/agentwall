// Package attack replays scripted attack scenarios against mock MCP servers
// through the real proxy and firewall and scores the result.
package attack

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Arsh624/agentwall/internal/firewall"
	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/mockserver"
	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/Arsh624/agentwall/internal/proxy"
)

type Scenario struct {
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	Kind        string                         `json:"kind"` // "attack" or "benign"
	Policy      string                         `json:"policy"`
	Secrets     map[string]string              `json:"secrets"`
	Servers     map[string]mockserver.Scenario `json:"servers"`
	Steps       []Step                         `json:"steps"`
}

type Step struct {
	Session     string          `json:"session"`
	Server      string          `json:"server"`
	List        bool            `json:"list"`
	Tool        string          `json:"tool"`
	Args        json.RawMessage `json:"args"`
	Expect      string          `json:"expect"` // "allow" or "block"
	Contains    []string        `json:"contains"`
	NotContains []string        `json:"not_contains"`
}

type Result struct {
	Name   string
	Kind   string
	Passed bool   // attack: the firewall stopped it. benign: nothing was blocked.
	Detail string // when !Passed: which step failed and why
}

// Load reads and validates every *.json in fsys, sorted by file name.
func Load(fsys fs.FS) ([]Scenario, error) {
	files, err := fs.Glob(fsys, "*.json") // Glob returns sorted names
	if err != nil {
		return nil, err
	}
	var out []Scenario
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var sc Scenario
		if err := dec.Decode(&sc); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := sc.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, sc)
	}
	return out, nil
}

func (sc *Scenario) validate() error {
	if sc.Name == "" {
		return errors.New("name is empty")
	}
	if sc.Kind != "attack" && sc.Kind != "benign" {
		return fmt.Errorf("kind %q is not attack or benign", sc.Kind)
	}
	checks := false
	for i, s := range sc.Steps {
		n := i + 1
		if _, ok := sc.Servers[s.Server]; !ok {
			return fmt.Errorf("step %d: unknown server %q", n, s.Server)
		}
		if s.List == (s.Tool != "") {
			return fmt.Errorf("step %d: need exactly one of list and tool", n)
		}
		if s.Expect != "allow" && s.Expect != "block" {
			return fmt.Errorf("step %d: expect %q is not allow or block", n, s.Expect)
		}
		if s.Expect == "block" && sc.Kind == "benign" {
			return fmt.Errorf("step %d: a benign scenario cannot expect a block", n)
		}
		checks = checks || s.Expect == "block" || len(s.NotContains) > 0
	}
	if sc.Kind == "attack" && !checks {
		return errors.New("an attack scenario needs a block step or a not_contains check")
	}
	return nil
}

// conn is one agent session talking to one server through its own firewall.
type conn struct {
	agentW *jsonrpc.Writer
	agentR *jsonrpc.Reader
	close  func() error
}

func open(sc Scenario, dir, session, server string, pol *policy.Policy) (*conn, error) {
	fw, err := firewall.Open(firewall.Config{StateDir: dir, Server: server, Session: session, Policy: pol, Secrets: sc.Secrets})
	if err != nil {
		return nil, err
	}
	agentInR, agentInW := io.Pipe()
	agentOutR, agentOutW := io.Pipe()
	upInR, upInW := io.Pipe()
	upOutR, upOutW := io.Pipe()
	mock := sc.Servers[server] // a copy: Serve counts tools/list calls in it
	go func() { mockserver.Serve(upInR, upOutW, &mock); upOutW.Close() }()
	done := make(chan error, 1)
	go func() { done <- proxy.Run(agentInR, agentOutW, upInW, upOutR, fw.Hooks()) }()
	return &conn{
		agentW: jsonrpc.NewWriter(agentInW),
		agentR: jsonrpc.NewReader(agentOutR),
		close: func() error {
			agentInW.Close()
			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				err = errors.New("proxy did not shut down")
			}
			agentOutR.Close()
			return errors.Join(err, fw.Close())
		},
	}, nil
}

func (c *conn) call(req *jsonrpc.Message) (*jsonrpc.Message, error) {
	type res struct {
		m   *jsonrpc.Message
		err error
	}
	ch := make(chan res, 1)
	go func() {
		if err := c.agentW.Write(req); err != nil {
			ch <- res{nil, err}
			return
		}
		m, err := c.agentR.Read()
		ch <- res{m, err}
	}()
	select {
	case r := <-ch:
		return r.m, r.err
	case <-time.After(5 * time.Second):
		return nil, errors.New("timed out waiting for a reply")
	}
}

// Run replays one scenario through the real proxy and firewall, in a fresh temporary state directory.
func Run(sc Scenario) (res Result, err error) {
	res = Result{Name: sc.Name, Kind: sc.Kind}
	pol := policy.Default()
	if sc.Policy != "" {
		if pol, err = policy.Parse([]byte(sc.Policy)); err != nil {
			return res, err
		}
	}
	dir, err := os.MkdirTemp("", "agentwall-attack-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(dir)

	conns := map[[2]string]*conn{}
	defer func() {
		for _, c := range conns {
			err = errors.Join(err, c.close())
		}
	}()

	for i, s := range sc.Steps {
		session := cmp.Or(s.Session, "s1")
		key := [2]string{session, s.Server}
		c := conns[key]
		if c == nil {
			if c, err = open(sc, dir, session, s.Server, pol); err != nil {
				return res, err
			}
			conns[key] = c
		}
		req := &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(fmt.Sprint(i + 1)), Method: "tools/list"}
		name := "tools/list"
		if !s.List {
			name = s.Tool
			params := map[string]any{"name": s.Tool}
			if len(s.Args) > 0 {
				params["arguments"] = s.Args
			}
			req.Method = "tools/call"
			req.Params, _ = json.Marshal(params)
		}
		reply, err := c.call(req)
		if err != nil {
			return res, fmt.Errorf("step %d (%s): %w", i+1, name, err)
		}
		var line strings.Builder // the reply as the agent reads it: no HTML escaping, so checks for "<IMPORTANT>" work
		jsonrpc.NewWriter(&line).Write(reply)
		if d := check(s, reply, line.String()); d != "" {
			res.Detail = fmt.Sprintf("step %d (%s): %s", i+1, name, d)
			return res, nil
		}
	}
	res.Passed = true
	return res, nil
}

// check returns what is wrong with a reply, or "" if the step's expectations hold.
func check(s Step, reply *jsonrpc.Message, line string) string {
	blocked := reply.Error != nil && reply.Error.Code == proxy.CodeBlocked
	got := "allow"
	if blocked {
		got = "block"
	}
	if got != s.Expect {
		d := fmt.Sprintf("expected %s, got %s", s.Expect, got)
		if blocked {
			d += ": " + reply.Error.Message
		}
		return d
	}
	for _, c := range s.Contains {
		if !strings.Contains(line, c) {
			return fmt.Sprintf("reply lacks %q: %s", c, excerpt(line))
		}
	}
	for _, c := range s.NotContains {
		if strings.Contains(line, c) {
			return fmt.Sprintf("reply contains %q: %s", c, excerpt(line))
		}
	}
	return ""
}

func excerpt(s string) string {
	if r := []rune(s); len(r) > 120 {
		return string(r[:120]) + "..."
	}
	return s
}

// Report writes the table and the score line to w and reports whether everything passed.
func Report(w io.Writer, results []Result) bool {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tKIND\tRESULT")
	var attacks, blocked, benign, falsePos int
	for _, r := range results {
		word := "allowed"
		switch {
		case r.Kind == "attack":
			attacks++
			blocked += b2i(r.Passed)
			word = "blocked"
			if !r.Passed {
				word = "NOT BLOCKED"
			}
		default:
			benign++
			falsePos += b2i(!r.Passed)
			if !r.Passed {
				word = "FALSE POSITIVE"
			}
		}
		if r.Passed {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Name, r.Kind, word)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, r.Kind, word, r.Detail)
		}
	}
	tw.Flush()
	fmt.Fprintf(w, "\nblocked %d/%d attacks, false positives %d/%d\n", blocked, attacks, falsePos, benign)
	return blocked == attacks && falsePos == 0
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
