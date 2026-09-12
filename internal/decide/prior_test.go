package decide

import (
	"testing"

	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/protocol"
)

func entry(from string, act protocol.Action) protocol.PriorVerdict {
	return protocol.PriorVerdict{
		Phase:     protocol.PhaseRequest,
		Inspector: from,
		Verdict:   "allow",
		Actions:   []protocol.Action{act},
	}
}

// Скидка и наценка берутся целиком -- потолков у правил нет, числа держит
// загрузчик отправителя, -- а сумма прижата к −100…+900: измерение не бывает
// меньше нуля.
func TestEvaluatePrior(t *testing.T) {
	rules := []config.PriorRule{
		{From: "ip", Accept: []string{"threshold"}},
		{From: "action", Accept: []string{"skip"}},
	}

	ask := EvaluatePrior([]protocol.PriorVerdict{
		entry("ip", protocol.Action{Do: "threshold", Apply: "request", Delta: -50}),
	}, rules)

	if ask.Percent != -50 || ask.Skip {
		t.Fatalf("ask = %+v, want -50 taken whole without skip", ask)
	}

	if len(ask.Outcomes) != 1 || ask.Outcomes[0].Outcome != OutcomeApplied ||
		ask.Outcomes[0].Took != -50 {
		t.Fatalf("outcomes = %+v", ask.Outcomes)
	}

	floored := EvaluatePrior([]protocol.PriorVerdict{
		entry("ip", protocol.Action{Do: "threshold", Apply: "request", Delta: -500}),
	}, rules)

	if floored.Percent != PercentMin || floored.Outcomes[0].Outcome != OutcomeApplied {
		t.Fatalf("ask = %+v, want the sum floored at %d", floored, PercentMin)
	}

	skip := EvaluatePrior([]protocol.PriorVerdict{
		entry("action", protocol.Action{Do: "skip", Apply: "request"}),
	}, rules)

	if !skip.Skip {
		t.Fatalf("skip was not applied: %+v", skip)
	}

	// Просьба от отправителя без правила -- записанное молчание.
	silent := EvaluatePrior([]protocol.PriorVerdict{
		entry("modsec", protocol.Action{Do: "skip", Apply: "request"}),
	}, rules)

	if silent.Skip || silent.Outcomes[0].Outcome != OutcomeNoRule {
		t.Fatalf("no-rule ask leaked into the decision: %+v", silent)
	}
}

func TestScaleScore(t *testing.T) {
	cases := []struct {
		score, percent, want int
	}{
		{50, 0, 50},
		{50, -50, 25},
		{40, 50, 60},
		{50, -100, 0},
		{20, 900, 100},
	}

	for _, c := range cases {
		if got := ScaleScore(c.score, c.percent); got != c.want {
			t.Errorf("ScaleScore(%d, %d) = %d, want %d",
				c.score, c.percent, got, c.want)
		}
	}
}

// Правила приёма: оба глагола умеют ослаблять, поэтому имя отправителя
// обязательно, а чужие глаголы не грузятся вовсе.
func TestPriorValidation(t *testing.T) {
	bad := []config.PriorRule{
		{From: "*", Accept: []string{"skip"}},
		{From: "ip", Accept: []string{"challenge"}},
		{From: "ip", Accept: []string{"note"}},
		{From: "ip", Accept: []string{"reauth"}},
		{From: "ip", Accept: []string{"block"}},
		{From: "", Accept: []string{"skip"}},
		{From: "ip", Accept: []string{"skip"}, Apply: []string{"ip"}},
	}

	for i, r := range bad {
		p := config.Profile{Mode: config.ModeOff, Trigger: config.Trigger{
			Prior: []config.PriorRule{r},
		}}

		if err := p.Validate(); err == nil {
			t.Errorf("bad[%d] %+v was accepted", i, r)
		}
	}

	ok := config.Profile{Mode: config.ModeOff, Trigger: config.Trigger{
		Prior: []config.PriorRule{
			{From: "ip", Accept: []string{"threshold", "skip"},
				Codes: []string{"IP_ALLOWLIST"}},
			// Потолка нет: threshold с одним именем отправителя -- полное правило.
			{From: "action", Accept: []string{"threshold"}},
		},
	}}

	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid rule was rejected: %v", err)
	}
}
