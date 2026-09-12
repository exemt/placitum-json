package decide

import (
	"testing"

	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/protocol"
)

func at(n int) *int { return &n }

func phase(mode string, outcomes ...config.Outcome) Phase {
	return Phase{Mode: mode, Outcomes: outcomes}
}

// clientIP -- адрес запроса: подсеть и систему по нему разворачивает
// обработчик у кодера, Fire называет только охват.
const clientIP = "203.0.113.7"

// Просьба уезжает ответом этого же запроса, и ось у неё явная: модуль пишет её
// всегда, а пустая означала бы сообщение старого образца.
func TestFireAsk(t *testing.T) {
	ph := phase(config.ModeEnforce, config.Outcome{
		On: config.OnScore, At: at(40), To: "captcha", Do: protocol.DoChallenge,
	})

	fired := Fire(ph, Decision{Verdict: protocol.VerdictScore, Score: 40, Code: "JSON_INVALID"}, clientIP)

	if len(fired.Actions) != 1 || len(fired.Bans) != 0 {
		t.Fatalf("fired = %+v", fired)
	}

	got := fired.Actions[0]

	if got.To != "captcha" || got.Do != protocol.DoChallenge || got.Apply != protocol.ApplyRequest {
		t.Fatalf("action = %+v", got)
	}

	// Повод свой не назван -- едет код решения: иначе по записи не понять, на
	// чём инициатор сработал.
	if got.Code != "JSON_INVALID" {
		t.Fatalf("code = %q", got.Code)
	}

	if len(fired.Names) != 1 || fired.Names[0] != protocol.DoChallenge {
		t.Fatalf("names = %v", fired.Names)
	}
}

func TestFireOwnCodeWins(t *testing.T) {
	ph := phase(config.ModeEnforce, config.Outcome{
		On: config.OnAllow, To: "modsec", Do: protocol.DoThreshold,
		Delta: at(50), Code: "JSON_API_HOT",
	})

	fired := Fire(ph, Decision{Verdict: protocol.VerdictAllow}, clientIP)

	if len(fired.Actions) != 1 {
		t.Fatalf("fired = %+v", fired)
	}

	if fired.Actions[0].Code != "JSON_API_HOT" || fired.Actions[0].Delta != 50 {
		t.Fatalf("action = %+v", fired.Actions[0])
	}
}

func TestFireList(t *testing.T) {
	ph := phase(config.ModeEnforce, config.Outcome{
		On: config.OnDeny, List: "api_abusers", TTL: config.Duration(3600),
	})

	fired := Fire(ph, Decision{Verdict: protocol.VerdictDeny, Code: "JSON_INVALID"}, clientIP)

	if len(fired.Bans) != 1 || len(fired.Actions) != 0 {
		t.Fatalf("fired = %+v", fired)
	}

	ban := fired.Bans[0]

	if ban.Dataset != "api_abusers" || ban.Addr != clientIP || ban.Write != config.WriteAddr ||
		ban.TTL != 3600 {
		t.Fatalf("ban = %+v", ban)
	}

	if ban.Reason != "JSON_INVALID" {
		t.Fatalf("reason = %q", ban.Reason)
	}
}

// Сообщение без адреса приходит только от пробы: писать в набор нечего -- ни
// сам адрес, ни его подсеть.
func TestFireListWithoutAddress(t *testing.T) {
	ph := phase(config.ModeEnforce,
		config.Outcome{On: config.OnDeny, List: "api_abusers", TTL: config.Duration(3600)},
		config.Outcome{On: config.OnDeny, List: "nets", Write: config.WriteNetAll,
			TTL: config.Duration(3600)},
	)

	fired := Fire(ph, Decision{Verdict: protocol.VerdictDeny}, "")

	if len(fired.Bans) != 0 {
		t.Fatalf("bans = %+v", fired.Bans)
	}
}

func TestFireThreshold(t *testing.T) {
	ph := phase(config.ModeEnforce,
		config.Outcome{On: config.OnScore, At: at(40), List: "hot", TTL: config.Duration(60)},
		config.Outcome{On: config.OnScore, At: at(10), Below: true, List: "cold",
			TTL: config.Duration(60)},
	)

	cases := []struct {
		name  string
		score int
		want  []string
	}{
		{"over the threshold", 70, []string{"hot"}},
		{"between", 20, nil},
		{"under the low one", 5, []string{"cold"}},
		{"exactly at", 40, []string{"hot"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fired := Fire(ph, Decision{Verdict: protocol.VerdictScore, Score: tc.score}, clientIP)

			if len(fired.Names) != len(tc.want) {
				t.Fatalf("names = %v, want %v", fired.Names, tc.want)
			}

			for i, want := range tc.want {
				if fired.Names[i] != want {
					t.Fatalf("names = %v, want %v", fired.Names, tc.want)
				}
			}
		})
	}
}

/*
 * Наблюдение глушит только ответ модулю: инициаторы судят по решению enforce
 * и стреляют как в бою -- просьба уезжает соседу под поводом решения, а не
 * под кодом наблюдения.
 */
func TestFireObserveFiresOutward(t *testing.T) {
	ph := phase(config.ModeObserve,
		config.Outcome{On: config.OnScore, At: at(40), To: "captcha", Do: protocol.DoChallenge},
		config.Outcome{On: config.OnDeny, List: "api_abusers", TTL: config.Duration(60)},
	)

	d := Decision{
		Verdict:      protocol.VerdictAllow,
		Code:         CodeObserve,
		WouldVerdict: protocol.VerdictScore,
		WouldScore:   70,
		WouldCode:    CodeMismatch,
	}

	fired := Fire(ph, d, clientIP)

	if len(fired.Actions) != 1 || fired.Actions[0].Do != protocol.DoChallenge {
		t.Fatalf("actions = %+v, want the challenge ask", fired.Actions)
	}

	if fired.Actions[0].Code != CodeMismatch {
		t.Fatalf("code = %q, want the enforce reason, not the observe one", fired.Actions[0].Code)
	}

	if len(fired.Bans) != 0 || len(fired.Names) != 1 || fired.Names[0] != protocol.DoChallenge {
		t.Fatalf("fired = %+v", fired)
	}
}

// Наблюдение судит would-вердикт: allow, которым оно отвечает модулю, не его
// собственное решение и инициатор «на пропуске» дёргать не должен.
func TestFireObserveJudgesWouldVerdict(t *testing.T) {
	ph := phase(config.ModeObserve,
		config.Outcome{On: config.OnAllow, List: "seen", TTL: config.Duration(60)},
	)

	d := Decision{
		Verdict:      protocol.VerdictAllow,
		Code:         CodeObserve,
		WouldVerdict: protocol.VerdictDeny,
	}

	if fired := Fire(ph, d, clientIP); len(fired.Bans) != 0 || len(fired.Names) != 0 {
		t.Fatalf("fired = %+v: наблюдение судит решение enforce, а не свой allow", fired)
	}
}

func TestFireWithoutOutcomes(t *testing.T) {
	fired := Fire(phase(config.ModeEnforce), Decision{Verdict: protocol.VerdictAllow}, clientIP)

	if len(fired.Actions) != 0 || len(fired.Bans) != 0 {
		t.Fatalf("fired = %+v", fired)
	}
}

// Секции фаз независимы, и инициаторы у каждой свои: правило фазы ответа не
// имеет права выстрелить на запросе.
func TestPhasesCarryOwnOutcomes(t *testing.T) {
	p, err := config.ParseProfile("x", []byte(
		"mode: enforce\nschema: {kind: openapi, source: api}\n"+
			"request:\n  enabled: true\n  outcomes:\n"+
			"    - {on: deny, list: req, ttl: 1h}\n"+
			"response:\n  enabled: true\n  outcomes:\n"+
			"    - {on: deny, list: rsp, write: net_all, ttl: 1h}\n"))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	req := Fire(RequestPhase(p), Decision{Verdict: protocol.VerdictDeny}, clientIP)
	rsp := Fire(ResponsePhase(p), Decision{Verdict: protocol.VerdictDeny}, clientIP)

	if len(req.Bans) != 1 || req.Bans[0].Dataset != "req" {
		t.Fatalf("request bans = %+v", req.Bans)
	}

	if len(rsp.Bans) != 1 || rsp.Bans[0].Dataset != "rsp" || rsp.Bans[0].Write != config.WriteNetAll {
		t.Fatalf("response bans = %+v", rsp.Bans)
	}
}

// Кого писать в набор -- решает строка: адрес меняется дешевле всего, анонс
// уже нет, а система целиком -- решение другого масштаба. Разворачивает их
// обработчик у кодера; Fire называет охват и адрес.
func TestFireWritesSubject(t *testing.T) {
	cases := map[string]string{
		config.WriteAddr:   config.WriteAddr,
		config.WriteNet:    config.WriteNet,
		config.WriteNetAll: config.WriteNetAll,
		config.WriteASN:    config.WriteASN,
		"":                 config.WriteAddr,
	}

	for write, want := range cases {
		t.Run("write "+write, func(t *testing.T) {
			ph := phase(config.ModeEnforce, config.Outcome{
				On: config.OnDeny, List: "hot", Write: write,
				TTL: config.Duration(60),
			})

			fired := Fire(ph, Decision{Verdict: protocol.VerdictDeny}, clientIP)

			if len(fired.Bans) != 1 || fired.Bans[0].Write != want || fired.Bans[0].Addr != clientIP {
				t.Fatalf("bans = %+v, want write %q for %s", fired.Bans, want, clientIP)
			}
		})
	}
}
