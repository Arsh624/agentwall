package proxy

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/Arsh624/agentwall/internal/jsonrpc"
)

// HTTPHandler is Run for MCP's Streamable HTTP transport: the agent sends its
// JSON-RPC messages here and they go to the upstream URL through the same
// hooks. headers (the server's credentials) are set on every upstream request.
//
// shortcut: basic by design. JSON-RPC batches are refused.
func HTTPHandler(upstream string, headers map[string]string, h Hooks) http.Handler {
	return &httpProxy{upstream: upstream, headers: headers, hooks: h}
}

type httpProxy struct {
	upstream string
	headers  map[string]string
	hooks    Hooks
}

// notForwarded are headers that describe one hop or that we set ourselves.
var notForwarded = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "Upgrade": true, "Te": true, "Trailer": true,
	"Proxy-Authorization": true, "Proxy-Authenticate": true,
	"Host": true, "Content-Length": true,
	"Accept-Encoding": true, // we read the body, so it must not be compressed
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if !notForwarded[k] {
			dst[k] = vs
		}
	}
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Browsers put Origin on cross-site requests and MCP clients send none: refusing it
	// keeps a web page from using this local port, and the credentials we attach.
	if r.Header.Get("Origin") != "" {
		http.Error(w, "agentwall: requests from a browser are not allowed", http.StatusForbidden)
		return
	}

	var req *jsonrpc.Message // the request whose reply must go through OnResponse
	var body bytes.Buffer
	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(jsonrpc.MaxFrame)))
		if err != nil {
			http.Error(w, "agentwall: request too large", http.StatusRequestEntityTooLarge)
			return
		}
		m, err := jsonrpc.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, jsonrpc.ErrorResponse(nil, jsonrpc.CodeParseError, "agentwall: "+err.Error()))
			return
		}
		if m.Method != "" {
			if p.hooks.OnRequest != nil {
				if d := p.hooks.OnRequest(m); d.Deny {
					if m.IsRequest() {
						writeJSON(w, http.StatusOK, jsonrpc.ErrorResponse(m.ID, CodeBlocked, "agentwall blocked this call: "+d.Reason))
					} else {
						w.WriteHeader(http.StatusAccepted)
					}
					return
				}
			}
			if m.IsRequest() {
				req = m
			}
		}
		jsonrpc.NewWriter(&body).Write(m) // upstream gets what the hooks inspected
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, p.upstream, &body)
	if err != nil {
		http.Error(w, "agentwall: bad upstream URL", http.StatusBadGateway)
		return
	}
	copyHeaders(out.Header, r.Header)
	for k, v := range p.headers {
		out.Header.Set(k, v)
	}
	resp, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		log.Printf("agentwall: upstream: %v", err)
		http.Error(w, "agentwall: upstream server is unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	contentType := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(contentType, "text/event-stream"):
		w.WriteHeader(resp.StatusCode)
		p.stream(w, resp.Body, req)
	case req != nil && resp.StatusCode == http.StatusOK && strings.HasPrefix(contentType, "application/json"):
		raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(jsonrpc.MaxFrame)))
		m, perr := jsonrpc.Parse(raw)
		if err != nil || perr != nil || !m.IsResponse() || string(m.ID) != string(req.ID) {
			log.Printf("agentwall: dropped an upstream reply that does not answer the request")
			http.Error(w, "agentwall: upstream sent an invalid reply", http.StatusBadGateway)
			return
		}
		if p.hooks.OnResponse != nil {
			m = p.hooks.OnResponse(req, m)
		}
		writeJSON(w, http.StatusOK, m)
	default: // 202 for notifications, upstream errors, session termination
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func writeJSON(w http.ResponseWriter, status int, m *jsonrpc.Message) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	jsonrpc.NewWriter(w).Write(m)
}

// stream copies server-sent events, passing the reply to req through OnResponse.
// Every other event is re-sent as it came.
func (p *httpProxy) stream(w http.ResponseWriter, upstream io.Reader, req *jsonrpc.Message) {
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	var event, data []string // lines of the event being read
	size := 0
	br := bufio.NewReaderSize(upstream, 64<<10)
	for {
		line, err := jsonrpc.ReadLine(br)
		if size += len(line); err == jsonrpc.ErrFrameTooLarge || size > jsonrpc.MaxFrame {
			log.Printf("agentwall: upstream event larger than the limit, closing the stream")
			return
		}
		switch text := strings.TrimRight(string(line), "\r\n"); {
		case text != "":
			event = append(event, text)
			if d, ok := strings.CutPrefix(text, "data:"); ok {
				data = append(data, strings.TrimPrefix(d, " "))
			}
		case len(event) > 0: // a blank line ends the event
			for _, l := range p.rewrite(event, strings.Join(data, "\n"), req) {
				io.WriteString(w, l+"\n")
			}
			io.WriteString(w, "\n")
			flush()
			event, data, size = nil, nil, 0
		}
		if err != nil {
			return
		}
	}
}

// rewrite returns the lines of one event, with a reply's data replaced by its hooked version.
// An event that carries a reply nobody asked for is dropped.
func (p *httpProxy) rewrite(event []string, data string, req *jsonrpc.Message) []string {
	m, err := jsonrpc.Parse([]byte(data))
	switch {
	case err != nil:
		return event // comments, keep-alives
	case m.Method != "": // notifications and server requests
		if p.hooks.OnServerMessage == nil {
			return event
		}
		if d := p.hooks.OnServerMessage(m); d.Deny {
			// shortcut: a denied server request gets no answer, so upstream waits for one; POST an error back if a server needs it.
			log.Printf("agentwall: dropped %s from upstream: %s", m.Method, d.Reason)
			return nil
		}
	case !m.IsResponse():
		return event
	case req == nil || string(m.ID) != string(req.ID):
		log.Printf("agentwall: dropped upstream response with unknown id %s", m.ID)
		return nil
	case p.hooks.OnResponse != nil:
		m = p.hooks.OnResponse(req, m)
	}
	var out strings.Builder
	jsonrpc.NewWriter(&out).Write(m)
	var lines []string
	for _, l := range event {
		if !strings.HasPrefix(l, "data:") {
			lines = append(lines, l)
		}
	}
	return append(lines, "data: "+strings.TrimSuffix(out.String(), "\n"))
}
