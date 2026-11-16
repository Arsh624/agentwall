package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"

	"gopkg.in/yaml.v3"
)

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
	Ask   Action = "ask"
)

const (
	TagUntrusted = "untrusted_source"
	TagPrivate   = "private_source"
	TagEgress    = "egress_sink"
)

type Decision struct {
	Action Action
	Reason string // human-readable; empty for a plain allow
}

type rule struct {
	arg string
	re  *regexp.Regexp
}

type tool struct {
	tags   []string
	action Action
	rules  []rule // sorted by arg name
}

type Policy struct {
	def     Action
	servers map[string]map[string]*tool
}

type rawPolicy struct {
	DefaultAction string `yaml:"default_action"`
	Servers       map[string]struct {
		Tools map[string]struct {
			Tags     []string          `yaml:"tags"`
			Action   string            `yaml:"action"`
			DenyArgs map[string]string `yaml:"deny_args"`
		} `yaml:"tools"`
	} `yaml:"servers"`
}

//go:embed default.yaml
var defaultYAML []byte

// Default returns the built-in policy. It panics if the embedded file is invalid.
func Default() *Policy {
	p, err := Parse(defaultYAML)
	if err != nil {
		panic(err)
	}
	return p
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func parseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case Allow, Deny, Ask:
		return a, nil
	}
	return "", fmt.Errorf("unknown action %q", s)
}

// Parse validates policy YAML from memory.
func Parse(data []byte) (*Policy, error) {
	var raw rawPolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p := &Policy{def: Allow, servers: map[string]map[string]*tool{}}
	if raw.DefaultAction != "" {
		a, err := parseAction(raw.DefaultAction)
		if err != nil {
			return nil, fmt.Errorf("policy: default_action: %w", err)
		}
		p.def = a
	}
	for sn, s := range raw.Servers {
		p.servers[sn] = map[string]*tool{}
		for tn, rt := range s.Tools {
			t := &tool{tags: rt.Tags}
			if rt.Action != "" {
				a, err := parseAction(rt.Action)
				if err != nil {
					return nil, fmt.Errorf("policy: %s/%s: %w", sn, tn, err)
				}
				t.action = a
			}
			for _, tag := range rt.Tags {
				if tag != TagUntrusted && tag != TagPrivate && tag != TagEgress {
					return nil, fmt.Errorf("policy: %s/%s: unknown tag %q", sn, tn, tag)
				}
			}
			for arg, expr := range rt.DenyArgs {
				re, err := regexp.Compile(expr)
				if err != nil {
					return nil, fmt.Errorf("policy: %s/%s: deny_args %q: %w", sn, tn, arg, err)
				}
				t.rules = append(t.rules, rule{arg, re})
			}
			slices.SortFunc(t.rules, func(a, b rule) int {
				if a.arg < b.arg {
					return -1
				} else if a.arg > b.arg {
					return 1
				}
				return 0
			})
			p.servers[sn][tn] = t
		}
	}
	return p, nil
}

func (p *Policy) lookup(server, name string) *tool {
	tools := p.servers[server]
	if t, ok := tools[name]; ok {
		return t
	}
	return tools["*"]
}

// Tags returns the tags of a tool (nil if none).
func (p *Policy) Tags(server, name string) []string {
	if t := p.lookup(server, name); t != nil {
		return t.tags
	}
	return nil
}

// Decide applies the policy to one tool call.
func (p *Policy) Decide(server, name string, args json.RawMessage) Decision {
	t := p.lookup(server, name)
	action := p.def
	if t != nil && t.action != "" {
		action = t.action
	}
	if t != nil && len(t.rules) > 0 && len(bytes.TrimSpace(args)) > 0 {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(args, &m); err != nil {
			return Decision{Deny, "arguments are not a JSON object"}
		}
		for _, r := range t.rules {
			raw, ok := m[r.arg]
			if !ok {
				continue
			}
			var text string
			if json.Unmarshal(raw, &text) != nil {
				var buf bytes.Buffer
				if json.Compact(&buf, raw) != nil {
					continue
				}
				text = buf.String()
			}
			if r.re.MatchString(text) {
				return Decision{Deny, fmt.Sprintf("argument %q matches deny rule", r.arg)}
			}
		}
	}
	switch action {
	case Deny:
		return Decision{Deny, "tool is denied by policy"}
	case Ask:
		return Decision{Ask, "tool needs approval"}
	}
	return Decision{Allow, ""}
}
