package decide

import (
	"math"

	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/protocol"
)

const (
	PercentMin = -100
	PercentMax = 900
)

const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
)

type Ask struct {
	Skip     bool
	Percent  int
	Outcomes []ActionOutcome
}

type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Delta int    `json:"delta,omitempty"`
	Value int    `json:"value,omitempty"`

	Took    int    `json:"took,omitempty"`
	Outcome string `json:"outcome"`
}

func EvaluatePrior(entries []protocol.PriorVerdict, rules []config.PriorRule) Ask {
	var a Ask

	for _, v := range entries {
		for _, act := range v.Actions {
			a.deliver(v.Inspector, act, rules)
		}
	}

	if a.Percent < PercentMin {
		a.Percent = PercentMin
	}

	if a.Percent > PercentMax {
		a.Percent = PercentMax
	}

	return a
}

func (a *Ask) deliver(from string, act protocol.Action, rules []config.PriorRule) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Delta:   act.Delta,
		Value:   act.Value,
		Outcome: OutcomeNoRule,
	}

	for _, r := range rules {
		if r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsAxis(act.Scope()) || !r.WantsCode(act.Code) {
			continue
		}

		switch act.Do {
		case protocol.DoSkip:
			a.Skip = true
			out.apply(0)

		case protocol.DoThreshold:
			a.Percent += act.Delta
			out.apply(act.Delta)
		}
	}

	a.Outcomes = append(a.Outcomes, out)
}

func (o *ActionOutcome) apply(took int) {
	o.Outcome = OutcomeApplied
	o.Took += took
}

func ScaleScore(score, percent int) int {
	if percent == 0 || score <= 0 {
		return max(score, 0)
	}

	scaled := int(math.Round(float64(score) * (1 + float64(percent)/100)))

	if scaled < 0 {
		scaled = 0
	}

	return min(scaled, 100)
}
