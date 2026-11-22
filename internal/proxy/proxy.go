package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

// CodeBlocked is the JSON-RPC error code the agent gets for a denied call.
const CodeBlocked = -32001

type Decision struct {
	Deny   bool
	Reason string // shown to the agent
	Ask    string // non-empty: ask the user this in the agent (MCP elicitation) before forwarding
}

// Hooks are the firewall's view of the traffic. Nil hooks make the proxy transparent.
// OnRequest and OnResponse run on different goroutines.
type Hooks struct {
	// OnRequest sees every request and notification from the agent before upstream does.
	OnRequest func(req *jsonrpc.Message) Decision
	// OnResponse sees each upstream response with the request that caused it and
	// returns the (non-nil) response to deliver to the agent.
	OnResponse func(req, resp *jsonrpc.Message) *jsonrpc.Message
	// OnServerMessage sees every notification and request upstream sends the agent,
	// and may rewrite it in place. A denied request is answered with an error for upstream.
	OnServerMessage func(m *jsonrpc.Message) Decision
	// OnAnswer gets the outcome of a question asked for a Decision with Ask and returns
	// the final decision (it may still deny an approved call). Nil: follow the user.
	OnAnswer func(req *jsonrpc.Message, approved bool, why string) Decision
}

// cancelledID is the id of the request a notifications/cancelled message gives up on, or "".
func cancelledID(m *jsonrpc.Message) string {
	if m.Method != "notifications/cancelled" {
		return ""
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	json.Unmarshal(m.Params, &p)
	return string(p.RequestID)
}

// Run pipes frames between the agent and the upstream server until upstream
// closes its output. When the agent closes its side, upstream's input is closed.
func Run(agentIn io.Reader, agentOut io.Writer, upIn io.WriteCloser, upOut io.Reader, h Hooks) error {
	toAgent, toUp := jsonrpc.NewWriter(agentOut), jsonrpc.NewWriter(upIn)
	var mu sync.Mutex
	// shortcut: a request upstream never answers and the agent never cancels stays here until the process exits.
	pending := map[string]*jsonrpc.Message{} // request id → request, until its response arrives or the agent cancels it
	qs := newAsks()

	// finish ends a question; the first of answer, timeout and cancel wins, the rest find nothing.
	finish := func(qid string, approved bool, why string) {
		call, ok := qs.take(qid)
		if !ok {
			return
		}
		d := Decision{Deny: !approved, Reason: why}
		if h.OnAnswer != nil {
			d = h.OnAnswer(call, approved, why)
		}
		if d.Deny {
			toAgent.Write(jsonrpc.ErrorResponse(call.ID, CodeBlocked, "agentwall blocked this call: "+d.Reason))
			return
		}
		mu.Lock()
		pending[string(call.ID)] = call
		mu.Unlock()
		toUp.Write(call)
	}

	go func() {
		defer upIn.Close()
		r := jsonrpc.NewReader(agentIn)
		for {
			m, err := r.Read()
			var pe *jsonrpc.ParseError
			if errors.As(err, &pe) {
				toAgent.Write(jsonrpc.ErrorResponse(nil, jsonrpc.CodeParseError, "agentwall: "+err.Error()))
				continue
			}
			if err != nil {
				return
			}
			if isAnswer(m) { // the user answering one of our questions: never goes upstream
				approved, why := approval(m)
				finish(string(m.ID), approved, why)
				continue
			}
			if m.Method != "" {
				var d Decision
				if h.OnRequest != nil {
					d = h.OnRequest(m)
				}
				if d.Deny {
					if m.IsRequest() {
						toAgent.Write(jsonrpc.ErrorResponse(m.ID, CodeBlocked, "agentwall blocked this call: "+d.Reason))
					}
					continue
				}
				if d.Ask != "" && m.IsRequest() {
					q := qs.start(m, d.Ask)
					time.AfterFunc(askTimeout, func() { finish(string(q.ID), false, "no answer within "+askTimeout.String()) })
					toAgent.Write(q)
					continue
				}
				id := cancelledID(m)
				if id != "" && qs.cancel(id) {
					continue // upstream never saw the call, so it needs no cancellation
				}
				mu.Lock()
				if m.IsRequest() {
					pending[string(m.ID)] = m // before the write, so a fast response always finds it
				} else if id != "" {
					delete(pending, id) // the agent ignores a late answer, so the proxy drops it
				}
				mu.Unlock()
			}
			if toUp.Write(m) != nil {
				return
			}
		}
	}()

	r := jsonrpc.NewReader(upOut)
	for {
		m, err := r.Read()
		var pe *jsonrpc.ParseError
		if errors.As(err, &pe) {
			log.Printf("agentwall: dropped bad frame from upstream: %v", err)
			continue
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if m.IsResponse() {
			mu.Lock()
			req, ok := pending[string(m.ID)]
			delete(pending, string(m.ID))
			mu.Unlock()
			if !ok { // the agent never asked, so no hook could vet it
				log.Printf("agentwall: dropped upstream response with unknown id %s", m.ID)
				continue
			}
			if h.OnResponse != nil {
				m = h.OnResponse(req, m)
			}
		} else if m.Method != "" && h.OnServerMessage != nil {
			if d := h.OnServerMessage(m); d.Deny {
				if m.IsRequest() {
					toUp.Write(jsonrpc.ErrorResponse(m.ID, CodeBlocked, "agentwall blocked this request: "+d.Reason))
				}
				continue
			}
		}
		if err := toAgent.Write(m); err != nil {
			return err
		}
	}
}
