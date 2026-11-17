package jsonrpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const CodeParseError = -32700

// Message is any JSON-RPC 2.0 frame: a request (method + id), a notification
// (method, no id) or a response (result or error).
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (m *Message) hasID() bool { return len(m.ID) > 0 && string(m.ID) != "null" }

func (m *Message) IsRequest() bool      { return m.Method != "" && m.hasID() }
func (m *Message) IsNotification() bool { return m.Method != "" && !m.hasID() }
func (m *Message) IsResponse() bool     { return m.Method == "" && (m.Result != nil || m.Error != nil) }

// ErrorResponse builds an error reply to the request with the given id.
func ErrorResponse(id json.RawMessage, code int, msg string) *Message {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &Message{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}

// ParseError is a line that is not a valid JSON-RPC 2.0 message. The reader stays usable.
type ParseError struct {
	Line []byte
	Err  error
}

func (e *ParseError) Error() string { return "jsonrpc: bad frame: " + e.Err.Error() }
func (e *ParseError) Unwrap() error { return e.Err }

// MaxFrame caps one frame, so a hostile peer cannot make us buffer without end.
var MaxFrame = 64 << 20

// ErrFrameTooLarge ends a stream: after it the reader cannot find the next frame.
var ErrFrameTooLarge = errors.New("jsonrpc: frame larger than the limit")

// Reader reads newline-delimited frames (the MCP stdio framing).
type Reader struct {
	br  *bufio.Reader
	err error // sticky
}

func NewReader(r io.Reader) *Reader { return &Reader{br: bufio.NewReaderSize(r, 64<<10)} }

// Read returns the next frame, io.EOF at the end, or a *ParseError for a bad line.
func (r *Reader) Read() (*Message, error) {
	for r.err == nil {
		var line []byte
		var err error
		for { // like ReadBytes('\n'), but bounded
			var chunk []byte
			chunk, err = r.br.ReadSlice('\n')
			line = append(line, chunk...)
			if len(line) > MaxFrame {
				r.err = ErrFrameTooLarge
				return nil, r.err
			}
			if err != bufio.ErrBufferFull {
				break
			}
		}
		if line = bytes.TrimSpace(line); len(line) > 0 {
			return Parse(line)
		}
		r.err = err
	}
	return nil, r.err
}

// shortcut: JSON-RPC batches (arrays) are rejected; MCP dropped them in 2025-06-18. Add if an old server needs them.
// Parse decodes one frame. A bad frame is a *ParseError.
func Parse(line []byte) (*Message, error) {
	line = bytes.TrimSpace(line)
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, &ParseError{Line: line, Err: err}
	}
	if m.JSONRPC != "2.0" {
		return nil, &ParseError{Line: line, Err: fmt.Errorf("jsonrpc version %q, want \"2.0\"", m.JSONRPC)}
	}
	if m.Method == "" && !m.IsResponse() {
		return nil, &ParseError{Line: line, Err: errors.New("no method, result or error")}
	}
	return &m, nil
}

// Writer writes one frame per line. It is safe for concurrent use.
type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer {
	enc := json.NewEncoder(w) // Encode compacts raw fields and appends the newline
	enc.SetEscapeHTML(false)
	return &Writer{enc: enc}
}

func (w *Writer) Write(m *Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(m)
}
