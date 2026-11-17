package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

// upstream is a fake Streamable HTTP MCP server that records what it receives.
type upstream struct {
	mu      sync.Mutex
	bodies  []string
	headers []http.Header
	sse     bool // answer requests with an SSE stream instead of plain JSON
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.bodies = append(u.bodies, string(body))
	u.headers = append(u.headers, r.Header.Clone())
	u.mu.Unlock()

	w.Header().Set("Mcp-Session-Id", "sess-42")
	if r.Method == http.MethodGet { // the server-to-client stream
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keep-alive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
		return
	}
	var m jsonrpc.Message
	json.Unmarshal(body, &m)
	if !m.IsRequest() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	reply := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"secret-from-upstream"}]}}`, m.ID)
	if u.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n")
		fmt.Fprintf(w, "id: ev-7\nevent: message\ndata: %s\n\n", reply)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, reply)
}

func (u *upstream) seen() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.bodies)
}

// front starts the fake upstream and the proxy in front of it.
func front(t *testing.T, u *upstream, h Hooks) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(u)
	t.Cleanup(up.Close)
	p := httptest.NewServer(HTTPHandler(up.URL, map[string]string{"Authorization": "Bearer vault-token"}, h))
	t.Cleanup(p.Close)
	return p
}

func post(t *testing.T, url, body string, header ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var redactHook = Hooks{
	OnRequest: func(req *jsonrpc.Message) Decision {
		if strings.Contains(req.Method+string(req.Params), "evil") {
			return Decision{Deny: true, Reason: "evil tool"}
		}
		return Decision{}
	},
	OnResponse: func(req, resp *jsonrpc.Message) *jsonrpc.Message {
		resp.Result = json.RawMessage(strings.ReplaceAll(string(resp.Result), "secret-from-upstream", "[REDACTED] for "+req.Method))
		return resp
	},
}

const callGood = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"good"}}`

func TestHTTPJSONRoundTrip(t *testing.T) {
	u := &upstream{}
	p := front(t, u, redactHook)
	resp, body := post(t, p.URL, callGood, "Mcp-Session-Id", "sess-42", "Authorization", "Bearer agent-token")

	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("status %d, content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(body, "[REDACTED] for tools/call") || strings.Contains(body, "secret-from-upstream") {
		t.Fatalf("OnResponse must see the reply with its request: %s", body)
	}
	if resp.Header.Get("Mcp-Session-Id") != "sess-42" {
		t.Fatal("upstream response headers must reach the agent")
	}
	h := u.headers[0]
	if h.Get("Authorization") != "Bearer vault-token" {
		t.Fatalf("the vault credential must replace the agent's: %q", h.Get("Authorization"))
	}
	if h.Get("Mcp-Session-Id") != "sess-42" || !strings.Contains(u.bodies[0], `"name":"good"`) {
		t.Fatalf("request not forwarded intact: %v %s", h, u.bodies[0])
	}
}

func TestHTTPDeniedCallNeverReachesUpstream(t *testing.T) {
	u := &upstream{}
	p := front(t, u, redactHook)

	resp, body := post(t, p.URL, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"evil"}}`)
	var m jsonrpc.Message
	if err := json.Unmarshal([]byte(body), &m); err != nil || resp.StatusCode != 200 ||
		string(m.ID) != "7" || m.Error == nil || m.Error.Code != CodeBlocked || !strings.Contains(m.Error.Message, "evil tool") {
		t.Fatalf("want a JSON-RPC blocked error, got %d %s", resp.StatusCode, body)
	}
	resp, _ = post(t, p.URL, `{"jsonrpc":"2.0","method":"notifications/evil"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("a denied notification is swallowed with 202, got %d", resp.StatusCode)
	}
	if u.seen() != 0 {
		t.Fatalf("upstream saw %d denied messages", u.seen())
	}

	// notifications and responses from the agent pass through
	if resp, _ = post(t, p.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); resp.StatusCode != http.StatusAccepted || u.seen() != 1 {
		t.Fatalf("notification: status %d, upstream saw %d", resp.StatusCode, u.seen())
	}
}

func TestHTTPStreamedReplyGoesThroughTheHooks(t *testing.T) {
	u := &upstream{sse: true}
	p := front(t, u, redactHook)
	resp, body := post(t, p.URL, callGood)

	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	events := strings.Split(strings.TrimSpace(body), "\n\n")
	if len(events) != 2 || !strings.Contains(events[0], "notifications/progress") {
		t.Fatalf("want the notification then the reply, got %q", body)
	}
	if !strings.Contains(events[1], "id: ev-7") || !strings.Contains(events[1], "[REDACTED] for tools/call") || strings.Contains(body, "secret-from-upstream") {
		t.Fatalf("the streamed reply must be hooked and keep its event id: %q", events[1])
	}
}

func TestHTTPServerStreamPassesThrough(t *testing.T) {
	p := front(t, &upstream{}, redactHook)
	resp, err := http.Get(p.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "notifications/tools/list_changed") || !strings.Contains(string(b), ": keep-alive") {
		t.Fatalf("GET stream: %q", b)
	}
}

func TestHTTPServerMessagesGoThroughTheHook(t *testing.T) {
	h := redactHook
	h.OnServerMessage = func(m *jsonrpc.Message) Decision {
		if m.Method == "notifications/tools/list_changed" {
			return Decision{Deny: true, Reason: "test"}
		}
		m.Params = json.RawMessage(`"hooked"`)
		return Decision{}
	}
	p := front(t, &upstream{sse: true}, h)
	if _, body := post(t, p.URL, callGood); !strings.Contains(body, `"params":"hooked"`) || strings.Contains(body, `"progress":1`) {
		t.Fatalf("a notification on a reply stream must be hooked: %q", body)
	}
	resp, err := http.Get(p.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); strings.Contains(string(b), "list_changed") || !strings.Contains(string(b), ": keep-alive") {
		t.Fatalf("a denied message must be dropped from the GET stream: %q", b)
	}
}

func TestHTTPRejectsBrowsersAndBadFrames(t *testing.T) {
	u := &upstream{}
	p := front(t, u, redactHook)

	// a web page must not be able to drive the proxy and the credentials it adds
	if resp, _ := post(t, p.URL, callGood, "Origin", "https://evil.example"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a request with an Origin header must be refused, got %d", resp.StatusCode)
	}
	for _, bad := range []string{`not json`, `[` + callGood + `]`} {
		if resp, _ := post(t, p.URL, bad); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%q: want 400, got %d", bad, resp.StatusCode)
		}
	}
	if u.seen() != 0 {
		t.Fatalf("upstream saw %d refused requests", u.seen())
	}
}

func TestHTTPUpstreamDown(t *testing.T) {
	p := httptest.NewServer(HTTPHandler("http://127.0.0.1:1", nil, Hooks{}))
	defer p.Close()
	if resp, _ := post(t, p.URL, callGood); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", resp.StatusCode)
	}
}
