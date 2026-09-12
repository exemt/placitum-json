/*
 * Секция frame профиля: умолчания направлений, отвергаемые формы и то, что
 * схемы привязок кадра попадают в список документов профиля.
 */

package config

import (
	"strings"
	"testing"
)

const wsProfile = `
mode: enforce
schema:
  kind: jsonschema
  source: ""
request:
  enabled: false
response:
  enabled: false
frame:
  enabled: true
  bindings:
    - path: /ws/
      direction: c2s
      discriminator: { pointer: /type, value: msg }
      schema: chat_msg
    - path: /ws/
      schema: chat_any
  c2s:
    deny_response: ws_policy
`

func TestFrameProfileParsesWithDefaults(t *testing.T) {
	p, err := ParseProfile("ws", []byte(wsProfile))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if !p.Frame.Enabled || p.Request.Enabled || p.Response.Enabled {
		t.Fatalf("phases: frame=%v request=%v response=%v", p.Frame.Enabled, p.Request.Enabled, p.Response.Enabled)
	}

	// Умолчания строк: префикс и любое направление.
	if p.Frame.Bindings[1].Match != MatchPrefix || p.Frame.Bindings[1].Direction != DirectionAny {
		t.Errorf("binding defaults: %+v", p.Frame.Bindings[1])
	}

	// Умолчания направлений: клиент гейтит, выдача скорит.
	if p.Frame.C2S.Policy.Invalid.Action != ActionDeny || p.Frame.C2S.Policy.Opcode.Action != ActionDeny {
		t.Errorf("c2s defaults: %+v", p.Frame.C2S.Policy)
	}

	if p.Frame.S2C.Policy.Invalid.Action != ActionScore || p.Frame.S2C.Policy.Opcode.Action != ActionAllow {
		t.Errorf("s2c defaults: %+v", p.Frame.S2C.Policy)
	}

	if p.Frame.C2S.DenyResponse != "ws_policy" || p.Frame.S2C.DenyResponse != "ws_policy" {
		t.Errorf("deny responses: %q %q", p.Frame.C2S.DenyResponse, p.Frame.S2C.DenyResponse)
	}

	got := strings.Join(p.Sources(), ",")
	if got != "chat_msg,chat_any" {
		t.Errorf("sources = %q", got)
	}

	if p.Frame.Direction("s2c") != &p.Frame.S2C || p.Frame.Direction("nonsense") != &p.Frame.C2S {
		t.Error("Direction() does not pick the section")
	}

	if rules := (FrameRules{}).Rules(); len(rules) != 6 || rules[4].Outcome != OutcomeOpcode {
		t.Errorf("frame rules order: %+v", rules)
	}
}

func TestFrameProfileRejectsBadForms(t *testing.T) {
	cases := map[string]string{
		"openapi with frames": `
mode: enforce
schema: { kind: openapi, source: spec }
frame:
  enabled: true
  bindings: [{ path: /ws/, schema: chat }]
`,
		"no bindings and no source": `
mode: enforce
schema: { kind: jsonschema, source: "" }
request: { enabled: false }
response: { enabled: false }
frame: { enabled: true }
`,
		"bad direction": `
mode: enforce
schema: { kind: jsonschema, source: "" }
frame:
  enabled: true
  bindings: [{ path: /ws/, direction: up, schema: chat }]
`,
		"pointer without slash": `
mode: enforce
schema: { kind: jsonschema, source: "" }
frame:
  enabled: true
  bindings: [{ path: /ws/, discriminator: { pointer: type, value: msg }, schema: chat }]
`,
		"deny without response": `
mode: enforce
schema: { kind: jsonschema, source: "" }
request: { enabled: false }
response: { enabled: false }
frame:
  enabled: true
  bindings: [{ path: /ws/, schema: chat }]
  c2s: { deny_response: "" }
`,
		"unknown key": `
mode: enforce
schema: { kind: jsonschema, source: "" }
frame:
  enabled: true
  reassemble: true
  bindings: [{ path: /ws/, schema: chat }]
`,
	}

	for name, src := range cases {
		p, err := ParseProfile("t", []byte(src))
		if err == nil {
			err = p.Validate()
		}

		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFrameBindingMatches(t *testing.T) {
	b := FrameBinding{Path: "/ws/", Match: MatchPrefix, Direction: DirectionC2S, Subprotocol: "chat.v2"}

	if !b.Matches("/ws/chat", DirectionC2S, "chat.v2") {
		t.Error("prefix, direction and subprotocol should match")
	}

	if b.Matches("/ws/chat", DirectionS2C, "chat.v2") {
		t.Error("direction must be honoured")
	}

	if b.Matches("/ws/chat", DirectionC2S, "other") {
		t.Error("subprotocol must be honoured")
	}

	if b.Matches("/api", DirectionC2S, "chat.v2") {
		t.Error("path must be honoured")
	}

	any := FrameBinding{Path: "/ws/chat", Match: MatchExact, Direction: DirectionAny}

	if !any.Matches("/ws/chat", DirectionS2C, "") || any.Matches("/ws/chat/x", DirectionS2C, "") {
		t.Error("exact match with any direction")
	}
}
