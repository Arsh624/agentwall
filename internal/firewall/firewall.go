// Package firewall turns policy, audit and (later) flow, pin, vault and detect
// into the proxy's hooks. One Firewall guards one upstream server.
package firewall

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/agentwall/agentwall/internal/audit"
	"github.com/agentwall/agentwall/internal/jsonrpc"
	"github.com/agentwall/agentwall/internal/policy"
	"github.com/agentwall/agentwall/internal/proxy"
)

type Firewall struct {
	Server  string // name the policy knows this upstream by
	Session string
	Policy  *policy.Policy
	Audit   *audit.Log
	Ask     func(question string) bool // nil: every "ask" is denied
}

func (f *Firewall) Hooks() proxy.Hooks {
	return proxy.Hooks{OnRequest: f.onRequest}
}

func (f *Firewall) onRequest(req *jsonrpc.Message) proxy.Decision {
	if req.Method != "tools/call" {
		return proxy.Decision{}
	}
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &call); err != nil || call.Name == "" {
		return proxy.Decision{Deny: true, Reason: "malformed tools/call"}
	}

	d := f.Policy.Decide(f.Server, call.Name, call.Arguments)
	if d.Action == policy.Ask {
		if f.Ask != nil && f.Ask(fmt.Sprintf("allow %s/%s?", f.Server, call.Name)) {
			d = policy.Decision{Action: policy.Allow, Reason: "approved by the user"}
		} else {
			d = policy.Decision{Action: policy.Deny, Reason: d.Reason + ", and no approval was given"}
		}
	}
	if d.Action != policy.Deny && d.Action != policy.Allow { // never forward on a decision we don't understand
		d = policy.Decision{Action: policy.Deny, Reason: "unknown policy action " + string(d.Action)}
	}

	err := f.Audit.Append(audit.Entry{
		Session: f.Session, Server: f.Server, Tool: call.Name,
		ArgsHash: audit.HashArgs(call.Arguments), Decision: string(d.Action), Reason: d.Reason,
	})
	if err != nil {
		log.Printf("agentwall: audit log: %v", err)
		return proxy.Decision{Deny: true, Reason: "the audit log is unavailable"} // no unlogged calls
	}
	return proxy.Decision{Deny: d.Action == policy.Deny, Reason: d.Reason}
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
