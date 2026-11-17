package jsonrpc

import (
	"errors"
	"strings"
	"testing"
)

func TestFrameSizeIsCapped(t *testing.T) {
	old := MaxFrame
	MaxFrame = 1 << 10
	defer func() { MaxFrame = old }()

	ok := `{"jsonrpc":"2.0","method":"` + strings.Repeat("a", 900) + `"}`
	tooBig := `{"jsonrpc":"2.0","method":"` + strings.Repeat("a", 5000) + `"}`

	if _, err := NewReader(strings.NewReader(ok + "\n")).Read(); err != nil {
		t.Fatalf("a frame under the cap must pass: %v", err)
	}
	r := NewReader(strings.NewReader(tooBig + "\n" + ok + "\n"))
	if _, err := r.Read(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge, got %v", err)
	}
	var pe *ParseError
	if _, err := r.Read(); !errors.Is(err, ErrFrameTooLarge) || errors.As(err, &pe) {
		t.Fatalf("an oversized frame ends the stream for good (not a skippable parse error), got %v", err)
	}
	// an endless line with no newline must not be buffered forever either
	if _, err := NewReader(strings.NewReader(strings.Repeat("x", 1<<16))).Read(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge for an unterminated line, got %v", err)
	}
}

func TestParse(t *testing.T) {
	m, err := Parse([]byte(` {"jsonrpc":"2.0","id":1,"method":"ping"} `))
	if err != nil || !m.IsRequest() {
		t.Fatalf("Parse: %+v, %v", m, err)
	}
	if _, err := Parse([]byte(`[]`)); err == nil {
		t.Fatal("a batch must be rejected")
	}
}
