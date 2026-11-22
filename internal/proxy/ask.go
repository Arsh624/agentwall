package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

// askTimeout is how long a question may stay unanswered before the call is denied.
var askTimeout = 5 * time.Minute

// askPrefix starts the id of every question the proxy asks (a JSON string, so with its quote).
const askPrefix = `"agentwall-`

// asks holds the open questions of one proxy. The answer, the timeout and the
// agent cancelling the call race to end a question; take and cancel let exactly
// one of them win (modelled and checked in spec/Ask.tla).
type asks struct {
	mu     sync.Mutex
	n      int
	open   map[string]*jsonrpc.Message // question id → the call it is about
	byCall map[string]string           // call id → question id
}

func newAsks() *asks {
	return &asks{open: map[string]*jsonrpc.Message{}, byCall: map[string]string{}}
}

// start opens a question about call and returns the elicitation request to send the agent.
func (a *asks) start(call *jsonrpc.Message, text string) *jsonrpc.Message {
	a.mu.Lock()
	a.n++
	qid := fmt.Sprintf(`%s%d"`, askPrefix, a.n)
	a.open[qid] = call
	a.byCall[string(call.ID)] = qid
	a.mu.Unlock()
	params, _ := json.Marshal(map[string]any{
		"message": text,
		"requestedSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"allow": map[string]any{"type": "boolean", "title": "Allow this call",
					"description": "agentwall will forward the call only if you allow it"},
			},
			"required": []string{"allow"},
		},
	})
	return &jsonrpc.Message{JSONRPC: "2.0", ID: json.RawMessage(qid), Method: "elicitation/create", Params: params}
}

// take ends a question and returns its call; false if it already ended (late answer, timeout, cancel).
func (a *asks) take(qid string) (*jsonrpc.Message, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	call, ok := a.open[qid]
	if ok {
		delete(a.open, qid)
		delete(a.byCall, string(call.ID))
	}
	return call, ok
}

// cancel ends the question about a call the agent gave up on; true if there was one.
func (a *asks) cancel(callID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	qid, ok := a.byCall[callID]
	if ok {
		delete(a.byCall, callID)
		delete(a.open, qid)
	}
	return ok
}

func isAnswer(m *jsonrpc.Message) bool {
	return m.Method == "" && strings.HasPrefix(string(m.ID), askPrefix)
}

// approval reads the agent's answer: only an accepted form with allow = true approves.
func approval(m *jsonrpc.Message) (bool, string) {
	if m.Error != nil {
		return false, "the agent could not show the question: " + m.Error.Message
	}
	var r struct {
		Action  string `json:"action"`
		Content struct {
			Allow bool `json:"allow"`
		} `json:"content"`
	}
	json.Unmarshal(m.Result, &r)
	switch {
	case r.Action == "accept" && r.Content.Allow:
		return true, "approved by the user in the agent"
	case r.Action == "accept":
		return false, "the user answered no in the agent"
	case r.Action == "decline":
		return false, "the user declined in the agent"
	}
	return false, "the user dismissed the question in the agent"
}
