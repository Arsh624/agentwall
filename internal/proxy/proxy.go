package proxy

import (
	"errors"
	"io"
	"log"
	"sync"

	"github.com/agentwall/agentwall/internal/jsonrpc"
)

// CodeBlocked is the JSON-RPC error code the agent gets for a denied call.
const CodeBlocked = -32001

type Decision struct {
	Deny   bool
	Reason string // shown to the agent
}

// Hooks are the firewall's view of the traffic. Nil hooks make the proxy transparent.
// OnRequest and OnResponse run on different goroutines.
type Hooks struct {
	// OnRequest sees every request and notification from the agent before upstream does.
	OnRequest func(req *jsonrpc.Message) Decision
	// OnResponse sees each upstream response with the request that caused it and
	// returns the (non-nil) response to deliver to the agent.
	OnResponse func(req, resp *jsonrpc.Message) *jsonrpc.Message
}

// Run pipes frames between the agent and the upstream server until upstream
// closes its output. When the agent closes its side, upstream's input is closed.
func Run(agentIn io.Reader, agentOut io.Writer, upIn io.WriteCloser, upOut io.Reader, h Hooks) error {
	toAgent, toUp := jsonrpc.NewWriter(agentOut), jsonrpc.NewWriter(upIn)
	var mu sync.Mutex
	// shortcut: a request that upstream never answers stays here forever; expire entries if long sessions leak.
	pending := map[string]*jsonrpc.Message{} // request id → request, until its response arrives

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
			if m.Method != "" {
				if h.OnRequest != nil {
					if d := h.OnRequest(m); d.Deny {
						if m.IsRequest() {
							toAgent.Write(jsonrpc.ErrorResponse(m.ID, CodeBlocked, "agentwall blocked this call: "+d.Reason))
						}
						continue
					}
				}
				if m.IsRequest() {
					mu.Lock()
					pending[string(m.ID)] = m // before the write, so a fast response always finds it
					mu.Unlock()
				}
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
		}
		if err := toAgent.Write(m); err != nil {
			return err
		}
	}
}
