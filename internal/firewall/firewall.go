// Package firewall turns policy, audit, taint, fingerprints, pins, redaction
// and injection heuristics into the proxy's hooks. One Firewall guards one upstream server.
package firewall

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Arsh624/agentwall/internal/audit"
	"github.com/Arsh624/agentwall/internal/detect"
	"github.com/Arsh624/agentwall/internal/flow"
	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/pin"
	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/Arsh624/agentwall/internal/proxy"
	"github.com/Arsh624/agentwall/internal/session"
	"github.com/Arsh624/agentwall/internal/vault"
)

type Firewall struct {
	Server  string           // name the policy knows this upstream by
	Session *session.Session // taint shared with the agent's other servers
	Policy  *policy.Policy
	Audit   *audit.Log
	Prints  *flow.Store                // fingerprints of private text, shared across sessions
	Pins    *pin.Store                 // hashes of the tool definitions the user has accepted
	Redact  *vault.Redactor            // strips secrets from everything upstream answers
	Ask     func(question string) bool // nil: every "ask" is denied
	Elicit  bool                       // the transport can ask in the agent (stdio); used when the agent can too

	clientElicits atomic.Bool // the agent declared the elicitation capability in initialize
	mu            sync.Mutex
	hidden        map[string]bool // tools whose definition changed since it was pinned
}

// Config is what one agentwall process needs to guard one server.
type Config struct {
	StateDir string // shared by every agentwall process of this user
	Server   string // name the policy knows the upstream by
	Session  string // shared by the agentwall processes of one agent
	Policy   *policy.Policy
	Secrets  map[string]string // vault values to redact, by name
	Ask      func(question string) bool
	Elicit   bool   // ask in the agent through MCP elicitation when it supports it (stdio only)
	AuditKey []byte // signs audit entries; nil writes them unsigned
}

func AuditPath(stateDir string) string { return filepath.Join(stateDir, "audit.jsonl") }
func PinsDir(stateDir string) string   { return filepath.Join(stateDir, "pins") }

// Open builds a Firewall on the shared state directory. Close it when done.
func Open(c Config) (*Firewall, error) {
	log, err := audit.OpenSigned(AuditPath(c.StateDir), c.AuditKey)
	if err != nil {
		return nil, err
	}
	sess, err := session.Open(c.StateDir, c.Session)
	if err != nil {
		log.Close()
		return nil, err
	}
	prints, err := flow.OpenStore(filepath.Join(c.StateDir, "fingerprints"))
	if err != nil {
		log.Close()
		return nil, err
	}
	return &Firewall{Server: c.Server, Session: sess, Policy: c.Policy, Audit: log, Prints: prints,
		Pins: pin.Open(PinsDir(c.StateDir)), Redact: vault.NewRedactor(c.Secrets), Ask: c.Ask, Elicit: c.Elicit}, nil
}

func (f *Firewall) Close() error {
	return errors.Join(f.Audit.Close(), f.Prints.Close())
}

func (f *Firewall) Hooks() proxy.Hooks {
	return proxy.Hooks{OnRequest: f.onRequest, OnResponse: f.onResponse, OnServerMessage: f.onServerMessage, OnAnswer: f.onAnswer}
}

// onAnswer audits the user's answer to a question asked in the agent and gives the final decision.
func (f *Firewall) onAnswer(req *jsonrpc.Message, approved bool, why string) proxy.Decision {
	var call callParams
	json.Unmarshal(req.Params, &call) // canonical since onRequest
	decision := policy.Deny
	if approved {
		decision = policy.Allow
	}
	if err := f.audit(call.Name, call.Arguments, string(decision), why); err != nil {
		return proxy.Decision{Deny: true, Reason: "the audit log is unavailable"} // no unlogged calls
	}
	return proxy.Decision{Deny: !approved, Reason: why}
}

// onServerMessage vets what the server sends the agent on its own: logs, progress, list changes,
// and requests for roots, user input or the agent's model.
func (f *Firewall) onServerMessage(m *jsonrpc.Message) proxy.Decision {
	if m.Method == "sampling/createMessage" {
		// the server would write the model's prompt and read its answer: an injection and an egress channel no policy can see into
		const reason = "servers may not use the agent's model (sampling)"
		if f.audit(m.Method, m.Params, string(policy.Deny), reason) != nil {
			return proxy.Decision{Deny: true, Reason: "the audit log is unavailable"}
		}
		return proxy.Decision{Deny: true, Reason: reason}
	}
	var found []string
	if m.Params, found = f.Redact.JSON(m.Params); found != nil {
		slices.Sort(found)
		f.audit(m.Method, nil, "redact", "removed from a server message before the agent saw it: "+strings.Join(slices.Compact(found), ", "))
	}
	return proxy.Decision{}
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (f *Firewall) onRequest(req *jsonrpc.Message) proxy.Decision {
	if req.Method == "initialize" {
		var p struct {
			Capabilities struct {
				Elicitation json.RawMessage `json:"elicitation"`
			} `json:"capabilities"`
		}
		json.Unmarshal(req.Params, &p)
		f.clientElicits.Store(len(p.Capabilities.Elicitation) > 0 && string(p.Capabilities.Elicitation) != "null")
	}
	if req.Method != "tools/call" {
		return proxy.Decision{}
	}
	var call callParams
	params, err := canonical(req.Params)
	if err == nil {
		err = json.Unmarshal(params, &call)
	}
	if err != nil || call.Name == "" {
		return proxy.Decision{Deny: true, Reason: "malformed tools/call"}
	}
	req.Params = params // upstream gets what the policy checks, whatever its parser does with duplicate keys

	d := f.Policy.Decide(f.Server, call.Name, call.Arguments)
	f.mu.Lock()
	changed := f.hidden[call.Name]
	f.mu.Unlock()
	if changed {
		d = policy.Decision{Action: policy.Deny, Reason: fmt.Sprintf("the definition of this tool changed after it was pinned; "+
			"if the change is expected, run: agentwall approve %s/%s", f.Server, call.Name)}
	}
	if d.Action != policy.Deny && slices.Contains(f.Policy.Tags(f.Server, call.Name), policy.TagEgress) {
		if fd := f.flowRules(call.Arguments); fd.Action != policy.Allow {
			d = fd
		}
	}
	if d.Action == policy.Ask && f.Elicit && f.clientElicits.Load() { // the proxy asks; onAnswer audits the outcome
		return proxy.Decision{Reason: d.Reason, Ask: fmt.Sprintf("agentwall: allow %s/%s?\n\nWhy you are asked: %s.\nArguments: %s",
			f.Server, call.Name, d.Reason, shorten(string(call.Arguments), 300))}
	}
	if d.Action == policy.Ask {
		if f.Ask != nil && f.Ask(fmt.Sprintf("allow %s/%s? (%s)", f.Server, call.Name, d.Reason)) {
			d = policy.Decision{Action: policy.Allow, Reason: "approved by the user"}
		} else {
			d = policy.Decision{Action: policy.Deny, Reason: d.Reason + ", and no approval was given"}
		}
	}
	if d.Action != policy.Deny && d.Action != policy.Allow { // never forward on a decision we don't understand
		d = policy.Decision{Action: policy.Deny, Reason: "unknown policy action " + string(d.Action)}
	}

	if err := f.audit(call.Name, call.Arguments, string(d.Action), d.Reason); err != nil {
		return proxy.Decision{Deny: true, Reason: "the audit log is unavailable"} // no unlogged calls
	}
	return proxy.Decision{Deny: d.Action == policy.Deny, Reason: d.Reason}
}

// shorten cuts s to at most n bytes (on a rune boundary), marking the cut.
func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// canonical re-encodes JSON as Go reads it: one value per key (the last), numbers as written.
func canonical(raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// flowRules judges a call to an egress tool: the stricter of the trifecta rule and the fingerprint rule.
func (f *Firewall) flowRules(args json.RawMessage) policy.Decision {
	d := policy.Decision{Action: policy.Allow}
	if f.Session.Has(session.Untrusted) && f.Session.Has(session.Private) {
		d = policy.Decision{Action: f.Policy.OnTrifecta(), Reason: "lethal trifecta: this session has read untrusted content " +
			"and private data, so a tool that sends data out is not allowed"}
		if d.Action == policy.Deny {
			return d
		}
	}
	leak, err := f.Prints.Contains(flow.Strings(args)...)
	if err != nil {
		log.Printf("agentwall: fingerprint store: %v", err)
		return policy.Decision{Action: policy.Deny, Reason: "the fingerprint store is unavailable"}
	}
	if leak && (d.Action == policy.Allow || f.Policy.OnFingerprint() == policy.Deny) {
		d = policy.Decision{Action: f.Policy.OnFingerprint(), Reason: "the arguments contain text that came from a private source"}
	}
	return d
}

// onResponse records what the agent is about to learn, before it learns it.
func (f *Firewall) onResponse(req, resp *jsonrpc.Message) *jsonrpc.Message {
	f.redact(req, resp)
	if req.Method == "tools/list" {
		return f.pinTools(resp)
	}
	if req.Method != "tools/call" {
		return resp
	}
	var call callParams
	json.Unmarshal(req.Params, &call) // validated by onRequest
	tags := f.Policy.Tags(f.Server, call.Name)

	err := f.taint(call, tags, policy.TagUntrusted, session.Untrusted)
	if err == nil {
		err = f.scan(call, resp)
	}
	if err == nil {
		err = f.taint(call, tags, policy.TagPrivate, session.Private)
	}
	if err == nil && slices.Contains(tags, policy.TagPrivate) {
		texts := flow.Strings(resp.Result)
		if resp.Error != nil {
			texts = append(texts, resp.Error.Message)
		}
		err = f.Prints.Add(texts...)
	}
	if err != nil { // the agent must not see data we failed to track
		log.Printf("agentwall: recording taint: %v", err)
		return jsonrpc.ErrorResponse(resp.ID, proxy.CodeBlocked, "agentwall withheld this result: its taint could not be recorded")
	}
	return resp
}

// redact strips secrets from any upstream answer, whatever the method.
func (f *Firewall) redact(req, resp *jsonrpc.Message) {
	var found []string
	resp.Result, found = f.Redact.JSON(resp.Result)
	if resp.Error != nil {
		var inMsg, inData []string
		resp.Error.Message, inMsg = f.Redact.Text(resp.Error.Message)
		resp.Error.Data, inData = f.Redact.JSON(resp.Error.Data)
		found = append(append(found, inMsg...), inData...)
	}
	if found == nil {
		return
	}
	slices.Sort(found)
	what := req.Method
	var call callParams
	if req.Method == "tools/call" && json.Unmarshal(req.Params, &call) == nil {
		what = call.Name
	}
	f.audit(what, call.Arguments, "redact", "removed from the answer before the agent saw it: "+strings.Join(slices.Compact(found), ", "))
}

// pinTools drops tools whose definition changed since first use (a rug pull) from a tools/list result.
func (f *Firewall) pinTools(resp *jsonrpc.Message) *jsonrpc.Message {
	if resp.Error != nil {
		return resp
	}
	var result map[string]json.RawMessage
	var tools []json.RawMessage
	err := json.Unmarshal(resp.Result, &result)
	if err == nil {
		err = json.Unmarshal(result["tools"], &tools)
	}
	var status []pin.Status
	if err == nil {
		status, err = f.Pins.Check(f.Server, tools)
	}
	if err != nil { // an unchecked tool list must not reach the agent
		log.Printf("agentwall: checking tool pins: %v", err)
		return jsonrpc.ErrorResponse(resp.ID, proxy.CodeBlocked, "agentwall withheld the tool list: it could not be checked against the pinned tools")
	}

	kept := []json.RawMessage{}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hidden == nil {
		f.hidden = map[string]bool{}
	}
	for i, tool := range tools {
		var t struct{ Name, Description string }
		json.Unmarshal(tool, &t) // Check already required a name
		why := ""
		switch status[i] {
		case pin.Changed:
			why = "tool definition changed since it was pinned"
		case pin.New: // trust on first use, unless the definition itself is an attack
			if why = f.distrust(t.Name, t.Description, tool); why != "" {
				if err := f.Pins.Distrust(f.Server, t.Name); err != nil { // else the next list would trust it
					log.Printf("agentwall: distrusting %s/%s: %v", f.Server, t.Name, err)
					return jsonrpc.ErrorResponse(resp.ID, proxy.CodeBlocked, "agentwall withheld the tool list: a suspicious tool could not be recorded")
				}
			}
		}
		f.hidden[t.Name] = why != ""
		if why == "" {
			kept = append(kept, tool)
			continue
		}
		log.Printf("agentwall: tool %s/%s is hidden: %s; to accept it run: agentwall approve %s/%s",
			f.Server, t.Name, why, f.Server, t.Name)
		f.audit(t.Name, tool, "pin", why+"; hidden until approved")
	}
	result["tools"], _ = json.Marshal(kept)
	resp.Result, _ = json.Marshal(result)
	return resp
}

// distrust says why a tool seen for the first time must not be trusted, or "".
func (f *Firewall) distrust(name, description string, tool json.RawMessage) string {
	if r := detect.ScoreTool(string(tool)); r.Suspicious() {
		return "tool description looks like a prompt injection (" + strings.Join(r.Signals, ", ") + ")"
	}
	// shadowing: orders about another server's tool. shortcut: only names with _ or - count,
	// plain words (fetch, search) are everyday English; upgrade if an attack uses one.
	others, _ := f.Pins.Others(f.Server)
	for _, other := range others {
		names, _ := f.Pins.Names(other)
		for _, n := range names {
			if strings.ContainsAny(n, "_-") && regexp.MustCompile(`\b`+regexp.QuoteMeta(n)+`\b`).MatchString(description) {
				return fmt.Sprintf("tool description gives orders about another server's tool %s/%s", other, n)
			}
		}
	}
	return ""
}

// scan taints the session when a tool's output reads like a prompt injection.
// It never blocks by itself: the flow rules decide what an untrusted session may do.
func (f *Firewall) scan(call callParams, resp *jsonrpc.Message) error {
	if f.Session.Has(session.Untrusted) {
		return nil // already as distrusted as it gets
	}
	for _, text := range flow.Strings(resp.Result) {
		r := detect.Score(text)
		if !r.Suspicious() {
			continue
		}
		added, err := f.Session.Add(session.Untrusted)
		if added {
			f.audit(call.Name, call.Arguments, "detect", fmt.Sprintf("session is now untrusted: output of %s/%s looks like a prompt injection (%s)",
				f.Server, call.Name, strings.Join(r.Signals, ", ")))
		}
		return err
	}
	return nil
}

func (f *Firewall) taint(call callParams, tags []string, tag string, t session.Taint) error {
	if !slices.Contains(tags, tag) {
		return nil
	}
	added, err := f.Session.Add(t)
	if added {
		f.audit(call.Name, call.Arguments, "taint", fmt.Sprintf("session is now %s: %s/%s is tagged %s", t, f.Server, call.Name, tag))
	}
	return err
}

func (f *Firewall) audit(tool string, args json.RawMessage, decision, reason string) error {
	err := f.Audit.Append(audit.Entry{
		Session: f.Session.ID(), Server: f.Server, Tool: tool,
		ArgsHash: audit.HashArgs(args), Decision: decision, Reason: reason,
	})
	if err != nil {
		log.Printf("agentwall: audit log: %v", err)
	}
	return err
}

// TerminalAsk asks on the controlling terminal, because stdin and stdout carry
// the protocol. It answers false when there is no terminal.
func TerminalAsk(question string) bool {
	in, out := "/dev/tty", "/dev/tty"
	if runtime.GOOS == "windows" {
		in, out = "CONIN$", "CONOUT$"
	}
	w, err := os.OpenFile(out, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	defer w.Close()
	r, err := os.Open(in)
	if err != nil {
		return false
	}
	defer r.Close()
	return askOn(r, w, question, terminalAskTimeout)
}

// terminalAskTimeout bounds a terminal question: an agent can own the terminal,
// or no one may be watching it, and the call must not hang forever.
var terminalAskTimeout = 5 * time.Minute

// askOn writes the question to w and waits up to timeout for a "y" line on r.
func askOn(r io.Reader, w io.Writer, question string, timeout time.Duration) bool {
	fmt.Fprintf(w, "agentwall: %s [y/N, no answer in %s is no] ", question, timeout)
	answer := make(chan string, 1)
	go func() { // shortcut: on timeout this reader stays blocked until the terminal closes; one per unanswered question
		line, _ := bufio.NewReader(r).ReadString('\n')
		answer <- line
	}()
	select {
	case line := <-answer:
		return strings.EqualFold(strings.TrimSpace(line), "y")
	case <-time.After(timeout):
		fmt.Fprintln(w, "\nagentwall: no answer, the call is denied")
		return false
	}
}
