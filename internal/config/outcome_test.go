package config

import (
	"strings"
	"testing"
)

// profileWith -- минимальный профиль с секцией инициаторов у фазы запроса.
func profileWith(t *testing.T, outcomes string) (*Profile, error) {
	t.Helper()

	src := "mode: enforce\nschema: {kind: openapi, source: api}\nrequest:\n  enabled: true\n" +
		"  outcomes:\n" + outcomes

	p, err := ParseProfile("x", []byte(src))
	if err != nil {
		return nil, err
	}

	return p, p.Validate()
}

func TestOutcomeAccepts(t *testing.T) {
	cases := map[string]string{
		"ask on score": "    - {on: score, at: 40, to: captcha, do: challenge}\n",
		"ask below":    "    - {on: score, at: 10, below: true, to: modsec, do: skip}\n",
		"ask on allow": "    - {on: allow, to: vlai, do: threshold, delta: -50}\n",
		"note with axis": "    - {on: score, at: 60, to: captcha, do: note, apply: ip, " +
			"value: 25}\n",
		"list on deny":  "    - {on: deny, list: api_abusers, ttl: 1h}\n",
		"list on score": "    - {on: score, at: 80, list: api_abusers, ttl: 15m, code: JSON_HOT}\n",
		// Переключить группу модификаторов у rewrite: группа и сторона обе.
		"mutate group": "    - {on: score, at: 40, to: rewrite, do: mutate, group: mask, set: on}\n",
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := profileWith(t, src); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestOutcomeRejects(t *testing.T) {
	cases := map[string]string{
		// Триггер и его порог.
		"unknown on":       "    - {on: sneeze, list: x, ttl: 1h}\n",
		"score without at": "    - {on: score, list: x, ttl: 1h}\n",
		"at without score": "    - {on: allow, at: 40, list: x, ttl: 1h}\n",
		"at out of range":  "    - {on: score, at: 900, list: x, ttl: 1h}\n",
		"below on allow":   "    - {on: allow, below: true, list: x, ttl: 1h}\n",

		// Действие: ровно одно, и оно осмысленное.
		"neither do nor list": "    - {on: allow}\n",
		"both do and list": "    - {on: allow, to: captcha, do: challenge, list: x, " +
			"ttl: 1h}\n",
		"list without ttl":        "    - {on: allow, list: x}\n",
		"unknown verb":            "    - {on: allow, to: captcha, do: nuke}\n",
		"mutate without group":    "    - {on: allow, to: rewrite, do: mutate, set: on}\n",
		"mutate without set":      "    - {on: allow, to: rewrite, do: mutate, group: mask}\n",
		"group on skip":           "    - {on: allow, to: vlai, do: skip, group: mask}\n",
		"set on skip":             "    - {on: allow, to: vlai, do: skip, set: on}\n",
		"bad axis":                "    - {on: allow, to: captcha, do: challenge, apply: asn}\n",
		"note without axis":       "    - {on: allow, to: captcha, do: note, value: 10}\n",
		"threshold without delta": "    - {on: allow, to: modsec, do: threshold}\n",
		"threshold zero delta": "    - {on: allow, to: modsec, do: threshold, " +
			"delta: 0}\n",
		"delta out of range": "    - {on: allow, to: modsec, do: threshold, delta: 1000}\n",
		"note zero value": "    - {on: allow, to: captcha, do: note, apply: ip, " +
			"value: 0}\n",
		"bad code": "    - {on: allow, list: x, ttl: 1h, code: \"плохой повод\"}\n",

		// Просьба на отказе: deny обрывает фазу, доехать ей некуда.
		"ask on deny": "    - {on: deny, to: captcha, do: challenge}\n",
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := profileWith(t, src); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Ось досочиняется там, где выбора нет, и уезжает на провод явной: модуль
// пишет её всегда, и пустая означала бы сообщение старого образца.
func TestOutcomeAxisFilledIn(t *testing.T) {
	p, err := profileWith(t, "    - {on: allow, to: captcha, do: challenge}\n")
	if err != nil {
		t.Fatal(err)
	}

	if got := p.Request.Outcomes[0].Axis(); got != "request" {
		t.Fatalf("axis = %q, want request", got)
	}
}

func TestOutcomeMatches(t *testing.T) {
	at := 40
	score := Outcome{On: OnScore, At: &at}
	below := Outcome{On: OnScore, At: &at, Below: true}

	cases := []struct {
		name    string
		outcome Outcome
		verdict string
		score   int
		want    bool
	}{
		{"score at the threshold", score, "score", 40, true},
		{"score above", score, "score", 70, true},
		{"score below the threshold", score, "score", 39, false},
		{"below matches under", below, "score", 39, true},
		{"below ignores over", below, "score", 40, false},
		{"score rule ignores allow", score, "allow", 90, false},
		{"deny matches deny", Outcome{On: OnDeny}, "deny", 0, true},
		{"deny ignores allow", Outcome{On: OnDeny}, "allow", 0, false},
		{"allow matches allow", Outcome{On: OnAllow}, "allow", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.outcome.Matches(tc.verdict, tc.score); got != tc.want {
				t.Fatalf("matches = %v, want %v", got, tc.want)
			}
		})
	}
}

// Срок читается человеческой записью: секунды в файле, который правят руками,
// читаются хуже, чем ошибаются.
func TestParseDuration(t *testing.T) {
	cases := map[string]int{
		"":     0,
		"30s":  30,
		"15m":  900,
		"1h":   3600,
		"7d":   604800,
		"3600": 3600,
	}

	for src, want := range cases {
		got, err := ParseDuration(src)
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}

		if got != want {
			t.Fatalf("%q = %d, want %d", src, got, want)
		}
	}

	for _, bad := range []string{"-1h", "abc", "1w"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// Ошибка называет место: строка профиля, которую правил оператор.
func TestOutcomeErrorNamesTheRow(t *testing.T) {
	_, err := profileWith(t, "    - {on: allow, list: x}\n")
	if err == nil {
		t.Fatal("accepted")
	}

	if !strings.Contains(err.Error(), "request.outcomes[0]") {
		t.Fatalf("error does not name the row: %v", err)
	}
}
