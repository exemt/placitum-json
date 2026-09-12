/*
 * Кадры: выбор схемы по направлению, пути и дискриминатору, и что бывает,
 * когда правило не сошлось. Проверяется на профиле ws из поставки -- том же,
 * что стоит на стенде nginx/tests/ws.
 */

package schema

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/exemt/placitum-json/internal/config"
)

func wsContract(t *testing.T) *Contract {
	t.Helper()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store, err := config.LoadProfiles(filepath.Join("..", "..", "profiles"), NewCompiler(log), log)
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}

	set, ok := store.Current().Compiled().(*Set)
	if !ok {
		t.Fatal("compiled set is not a *Set")
	}

	c, ok := set.Contract("ws")
	if !ok {
		t.Fatal("profile ws has no contract")
	}

	return c
}

func frame(direction, body string) *FrameInput {
	return &FrameInput{Path: "/ws/chat", Direction: direction, Subprotocol: "chat.v2", Body: []byte(body)}
}

func TestFramePicksSchemaByDiscriminator(t *testing.T) {
	c := wsContract(t)
	checks := config.FrameChecks{Body: true}

	cases := map[string]struct {
		body string
		want string
	}{
		"msg ok":           {`{"type":"msg","text":"привет"}`, OutcomeOK},
		"join ok":          {`{"type":"join","room":"lobby"}`, OutcomeOK},
		"msg without text": {`{"type":"msg"}`, OutcomeMismatch},
		"join extra field": {`{"type":"join","room":"x","admin":true}`, OutcomeMismatch},
		"unknown type":     {`{"type":"kick","user":"bob"}`, OutcomeUnknownOperation},
		"no discriminator": {`{"q":"1' OR 1=1-- "}`, OutcomeUnknownOperation},
		"type is a number": {`{"type":1}`, OutcomeUnknownOperation},
		"empty frame":      {``, OutcomeOK},
	}

	for name, tc := range cases {
		res := c.Frame(frame(config.DirectionC2S, tc.body), checks, Options{MaxErrors: 5})

		if res.Outcome != tc.want {
			t.Errorf("%s: outcome %q, want %q (findings %v)", name, res.Outcome, tc.want, res.Findings)
		}
	}
}

func TestFrameBindingsHonourDirectionAndPath(t *testing.T) {
	c := wsContract(t)
	checks := config.FrameChecks{Body: true}

	// Правила профиля написаны для c2s: выдача приложения с тем же телом
	// контрактом не описана.
	if res := c.Frame(frame(config.DirectionS2C, `{"type":"msg","text":"hi"}`), checks, Options{}); res.Outcome != OutcomeUnknownOperation {
		t.Errorf("s2c: outcome %q, want unknown_operation", res.Outcome)
	}

	other := &FrameInput{Path: "/other", Direction: config.DirectionC2S, Body: []byte(`{"type":"msg","text":"hi"}`)}

	if res := c.Frame(other, checks, Options{}); res.Outcome != OutcomeUnknownOperation {
		t.Errorf("other path: outcome %q, want unknown_operation", res.Outcome)
	}

	if res := c.Frame(frame(config.DirectionC2S, `{"type":"msg","text":"hi"}`), config.FrameChecks{}, Options{}); res.Outcome != OutcomeOK {
		t.Errorf("body check off: outcome %q, want ok", res.Outcome)
	}
}

func TestPointerAndDiscriminator(t *testing.T) {
	doc, err := Decode([]byte(`{"a":{"b":[10,{"c":true}]},"x/y":"z","n":2.5}`))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		ptr, value string
		want       bool
	}{
		"nested number": {"/a/b/0", "10", true},
		"nested bool":   {"/a/b/1/c", "true", true},
		"escaped slash": {"/x~1y", "z", true},
		"float":         {"/n", "2.5", true},
		"missing":       {"/a/z", "1", false},
		"wrong value":   {"/a/b/0", "11", false},
		"object":        {"/a", "x", false},
		"bad index":     {"/a/b/9", "1", false},
	}

	for name, tc := range cases {
		got := discriminates(doc, &config.Discriminator{Pointer: tc.ptr, Value: tc.value})

		if got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
