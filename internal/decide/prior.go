/*
 * Просьбы соседей против правил приёма профиля.
 *
 * Из словаря канала инспектор применяет два глагола: threshold -- коэффициент
 * к счёту, который он отдаёт модулю (проценты, множитель 1 + delta/100; плюс
 * -- строже, минус -- скидка; пороги не двигаются), и skip -- не проверять
 * этот запрос вовсе. Исход каждой доставленной просьбы уезжает в
 * kind=inspector: молчание в ответ на просьбу и есть тот случай, который
 * потом разбирают.
 */

package decide

import (
	"math"

	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/protocol"
)

// Границы суммарного коэффициента: -100 -- счёт в ноль, +900 -- вдесятеро.
const (
	PercentMin = -100
	PercentMax = 900
)

// Исход одной просьбы. «Нет правила» -- полноправный исход, а не пропуск.
const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
)

/*
 * Ask -- что соседи попросили и что из этого прошло через правила профиля.
 * Нулевая структура означает «никто ничего не просил либо ни одно правило не
 * подошло», и это самый частый исход.
 */
type Ask struct {
	// Skip -- не проверять этот запрос вовсе. Действует только через правило с
	// именем отправителя, поэтому это решение оператора, а не соседа.
	Skip bool
	// Percent -- суммарный коэффициент к отдаваемому счёту, прижатый к
	// -100..+900: числа отдельных просьб держит загрузчик отправителя.
	Percent int
	// Outcomes -- по строке на каждую доставленную просьбу, для kind=inspector.
	Outcomes []ActionOutcome
}

/*
 * ActionOutcome -- что сосед просил и что из этого вышло у нас. Исходы «не
 * доставлено» сюда попасть не могут по построению: пассивный отправитель,
 * переполнение waf_actions_max и урезание по маршруту отсекаются до нас и
 * живут в записи модуля kind=request.
 */
type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Delta int    `json:"delta,omitempty"`
	Value int    `json:"value,omitempty"`

	// Took -- что мы взяли на самом деле: срезанный либо принятый процент.
	Took    int    `json:"took,omitempty"`
	Outcome string `json:"outcome"`
}

/*
 * EvaluatePrior -- все просьбы всех записей prior против правил профиля. Фазы
 * не фильтруются: секция сквозная, просьба с фазы запроса действует и на фазе
 * ответа -- «этот запрос» покрывает обе стороны транзакции.
 */
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

/*
 * deliver -- одна просьба против всех правил профиля. Цикл по действиям
 * снаружи, а не по правилам: исход у просьбы один, сколько бы правил её ни
 * зацепило.
 */
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

// apply -- правило подошло и просьба взята целиком: числа держит загрузчик
// отправителя, получатель их не режет. Несколько подошедших правил складывают
// took -- исход у просьбы один.
func (o *ActionOutcome) apply(took int) {
	o.Outcome = OutcomeApplied
	o.Took += took
}

/*
 * ScaleScore -- счёт, умноженный на коэффициент просьб соседей. Применяется к
 * тому, что инспектор отдаёт, а не к порогам: числа конфигурации не двигаются,
 * меняется цена поведения клиента на этом запросе. -100 даёт ноль; верх прижат
 * к 100, как любой score протокола.
 */
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
