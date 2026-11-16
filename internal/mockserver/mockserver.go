// Package mockserver is a tiny scripted MCP server for tests and the attack suite.
package mockserver

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/agentwall/agentwall/internal/jsonrpc"
)

// Scenario scripts the server. A tools/call for a tool missing from Calls
// echoes its arguments back as text.
type Scenario struct {
	Tools []json.RawMessage          `json:"tools"` // returned by tools/list
	Calls map[string]json.RawMessage `json:"calls"` // tool name → tools/call result
}

func Load(path string) (*Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sc Scenario
	return &sc, json.Unmarshal(b, &sc)
}

// Serve answers requests from in on out until in is closed.
func Serve(in io.Reader, out io.Writer, sc *Scenario) error {
	r, w := jsonrpc.NewReader(in), jsonrpc.NewWriter(out)
	for {
		req, err := r.Read()
		var pe *jsonrpc.ParseError
		if errors.As(err, &pe) {
			continue
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if !req.IsRequest() {
			continue
		}
		resp := &jsonrpc.Message{JSONRPC: "2.0", ID: req.ID}
		if result := sc.handle(req); result != nil {
			resp.Result, _ = json.Marshal(result)
		} else {
			resp.Error = &jsonrpc.Error{Code: -32601, Message: "method not found: " + req.Method}
		}
		if err := w.Write(resp); err != nil {
			return err
		}
	}
}

func (sc *Scenario) handle(req *jsonrpc.Message) any {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		return map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "mockserver", "version": "0"},
		}
	case "ping":
		return map[string]any{}
	case "tools/list":
		return map[string]any{"tools": sc.Tools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		json.Unmarshal(req.Params, &p)
		if result, ok := sc.Calls[p.Name]; ok {
			return result
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(p.Arguments)}}}
	}
	return nil
}
