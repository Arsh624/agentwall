package vault

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestTerminalEscapesAreStripped(t *testing.T) {
	r := NewRedactor(nil)
	// erase line + cursor up, an OSC 8 hyperlink with BEL and with ST, a full reset
	in := "ok\x1b[2K\x1b[1Ahidden\x1b]8;;https://evil.test\x07link\x1b]8;;\x1b\\ \x1bc done"
	out, found := r.Text(in)
	if out != "okhiddenlink  done" || !slices.Equal(found, []string{"terminal-escape"}) {
		t.Fatalf("got %q %v", out, found)
	}
	if out, _ := r.Text("x\u009b2Jy"); out != "xy" {
		t.Fatalf("one-character CSI not stripped: %q", out)
	}
	if out, found := r.Text("plain text, no escapes"); found != nil || out != "plain text, no escapes" {
		t.Fatalf("clean text changed: %q %v", out, found)
	}
	// JSON escaping must not hide one
	doc, found := r.JSON(json.RawMessage(`{"text":"a\u001b[31mred"}`))
	if found == nil || strings.Contains(string(doc), "u001b") {
		t.Fatalf("escape inside JSON not stripped: %s", doc)
	}
}
