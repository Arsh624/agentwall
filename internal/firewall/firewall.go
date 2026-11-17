// Package firewall turns policy, audit, taint and fingerprints (later pin,
// vault and detect) into the proxy's hooks. One Firewall guards one upstream server.
package firewall

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/Arsh624/agentwall/internal/audit"
	"github.com/Arsh624/agentwall/internal/flow"
	"github.com/Arsh624/agentwall/internal/jsonrpc"
	"github.com/Arsh624/agentwall/internal/policy"
	"github.com/Arsh624/agentwall/internal/proxy"
	"github.com/Arsh624/agentwall/internal/session"
)

type Firewall struct {
	Server  string           // name the policy knows this upstream by
	Session *session.Session // taint shared with the agent's other servers
	Policy  *policy.Policy
	Audit   *audit.Log
	Prints  *flow.Store                // fingerprints of private text, shared across sessions
	Ask     func(question string) bool // nil: every "ask" is denied
}

func (f *Firewall) Hooks() proxy.Hooks {
	return proxy.Hooks{OnRequest: f.onRequest, OnResponse: f.onResponse}
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (f *Firewall) onRequest(req *jsonrpc.Message) proxy.Decision {
	if req.Method != "tools/call" {
		return proxy.Decision{}
	}
	var call callParams
	if err := json.Unmarshal(req.Params, &call); err != nil || call.Name == "" {
		return proxy.Decision{Deny: true, Reason: "malformed tools/call"}
	}

	d := f.Policy.Decide(f.Server, call.Name, call.Arguments)
	if d.Action != policy.Deny && slices.Contains(f.Policy.Tags(f.Server, call.Name), policy.TagEgress) {
		if fd := f.flowRules(call.Arguments); fd.Action != policy.Allow {
			d = fd
		}
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
	if req.Method != "tools/call" {
		return resp
	}
	var call callParams
	json.Unmarshal(req.Params, &call) // validated by onRequest
	tags := f.Policy.Tags(f.Server, call.Name)

	err := f.taint(call, tags, policy.TagUntrusted, session.Untrusted)
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
	fmt.Fprintf(w, "agentwall: %s [y/N] ", question)
	line, _ := bufio.NewReader(r).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}
