package firewall

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MCP 2026-07-28 has no server-to-client requests: to ask the user, a server answers
// the call with resultType "input_required" and an elicitation form, and the client
// retries the same call with the user's answer in inputResponses plus the
// requestState it was given. agentwall signs that state so an answer only counts
// for the exact tool and arguments the user was shown.

const (
	approvalKey  = "agentwall_approval" // our key in inputRequests / inputResponses
	statePrefix  = "agentwall1."
	metaCaps     = "io.modelcontextprotocol/clientCapabilities"
	approvalForm = "allow"
)

// approvalTTL is how long a question's answer stays valid.
var approvalTTL = 5 * time.Minute

type answer struct {
	present  bool // the call carries an answer to an agentwall question
	approved bool
	why      string
}

type statePayload struct {
	Tool    string `json:"t"`
	Args    string `json:"a"` // hex SHA-256 of the canonical arguments
	Expires int64  `json:"e"`
}

func argsHash(args json.RawMessage) string {
	sum := sha256.Sum256(args)
	return hex.EncodeToString(sum[:])
}

func (f *Firewall) sign(payload []byte) []byte {
	m := hmac.New(sha256.New, f.stateKey)
	m.Write(payload)
	return m.Sum(nil)
}

func (f *Firewall) newState(call callParams) string {
	payload, _ := json.Marshal(statePayload{call.Name, argsHash(call.Arguments), time.Now().Add(approvalTTL).Unix()})
	enc := base64.RawURLEncoding
	return statePrefix + enc.EncodeToString(payload) + "." + enc.EncodeToString(f.sign(payload))
}

// checkState says why state does not approve call, or "" if it does.
func (f *Firewall) checkState(state string, call callParams) string {
	const mismatch = "the approval does not match this call"
	body, ok := strings.CutPrefix(state, statePrefix)
	p, s, ok2 := strings.Cut(body, ".")
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p)
	sig, err2 := enc.DecodeString(s)
	if !ok || !ok2 || err1 != nil || err2 != nil || !hmac.Equal(sig, f.sign(payload)) {
		return mismatch
	}
	var st statePayload
	if json.Unmarshal(payload, &st) != nil || st.Tool != call.Name || st.Args != argsHash(call.Arguments) {
		return mismatch
	}
	if time.Now().Unix() > st.Expires {
		return "the approval expired"
	}
	return ""
}

// takeAnswer removes agentwall's answer (our inputResponses entry and our requestState)
// from the call's params, so upstream gets the call as it was, and says what the user answered.
func (f *Firewall) takeAnswer(params json.RawMessage, call callParams) (json.RawMessage, answer, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(params, &top); err != nil {
		return params, answer{}, err
	}
	var responses map[string]json.RawMessage
	json.Unmarshal(top["inputResponses"], &responses)
	resp, ok := responses[approvalKey]
	if !ok {
		return params, answer{}, nil
	}
	delete(responses, approvalKey)
	if len(responses) == 0 {
		delete(top, "inputResponses")
	} else {
		top["inputResponses"], _ = json.Marshal(responses)
	}
	var state string
	json.Unmarshal(top["requestState"], &state)
	if strings.HasPrefix(state, statePrefix) {
		delete(top, "requestState") // shortcut: ours replaces upstream's; a server that also uses requestState on this call would lose its own
	}

	a := answer{present: true}
	if why := f.checkState(state, call); why != "" {
		a.why = why
	} else {
		var r struct {
			Action  string `json:"action"`
			Content map[string]any
		}
		json.Unmarshal(resp, &r)
		switch allow, _ := r.Content[approvalForm].(bool); {
		case r.Action == "accept" && allow:
			a.approved, a.why = true, "approved by the user in the agent"
		case r.Action == "accept":
			a.why = "the user answered no in the agent"
		case r.Action == "decline":
			a.why = "the user declined in the agent"
		default:
			a.why = "the user dismissed the question in the agent"
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(top); err != nil {
		return params, a, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), a, nil
}

// asksInBand says whether the request comes from a 2026-07-28 client that can show a form.
func asksInBand(params json.RawMessage) bool {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	json.Unmarshal(params, &p)
	var caps struct {
		Elicitation map[string]json.RawMessage `json:"elicitation"`
	}
	if json.Unmarshal(p.Meta[metaCaps], &caps) != nil || caps.Elicitation == nil {
		return false
	}
	_, form := caps.Elicitation["form"]
	return form || len(caps.Elicitation) == 0 // a bare {} means form support
}

// inputRequired is the reply that asks the user, in the agent, about call.
func (f *Firewall) inputRequired(call callParams, reason string) json.RawMessage {
	r, _ := json.Marshal(map[string]any{
		"resultType":   "input_required",
		"requestState": f.newState(call),
		"inputRequests": map[string]any{approvalKey: map[string]any{
			"method": "elicitation/create",
			"params": map[string]any{
				"mode":    "form",
				"message": fmt.Sprintf("agentwall: allow %s/%s?\n\nWhy you are asked: %s.\nArguments: %s", f.Server, call.Name, reason, shorten(string(call.Arguments), 300)),
				"requestedSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{approvalForm: map[string]any{"type": "boolean", "title": "Allow this call",
						"description": "agentwall forwards the call only if you allow it"}},
					"required": []string{approvalForm},
				},
			},
		}},
	})
	return r
}
