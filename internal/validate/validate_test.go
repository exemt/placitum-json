/*
 * Проверка на профилях из образа: то же, что увидит инспектор на стенде.
 *
 * Тест намеренно ходит в каталог profiles/, а не в свои фикстуры. Профили --
 * часть поставки, и опечатка в них ломает контур ровно так же, как ошибка в
 * коде; ловить её сборкой образа дешевле, чем прогоном на стенде.
 */

package validate_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/exemt/placitum-json/internal/body"
	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/decide"
	"github.com/exemt/placitum-json/internal/protocol"
	"github.com/exemt/placitum-json/internal/schema"
	"github.com/exemt/placitum-json/internal/validate"
)

func profilesDir() string {
	if dir := os.Getenv("JSON_PROFILES_DIR"); dir != "" {
		return dir
	}

	return filepath.Join("..", "..", "profiles")
}

func load(t *testing.T) *config.Snapshot {
	t.Helper()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store, err := config.LoadProfiles(profilesDir(), schema.NewCompiler(log), log)
	if err != nil {
		t.Fatalf("profiles: %v", err)
	}

	return store.Current()
}

// Каталог профилей поставки обязан подниматься целиком: разобраться, пройти
// проверку формы и скомпилироваться. Всё остальное в этом файле опирается на
// это.
func TestBundledProfiles(t *testing.T) {
	snap := load(t)

	for _, want := range []string{"default", "_probe", "api", "strict", "observe", "soft", "ws"} {
		if _, ok := snap.Profile(want); !ok {
			t.Errorf("profile %q is missing, got %v", want, snap.Names())
		}
	}

	set, ok := snap.Compiled().(*schema.Set)
	if !ok {
		t.Fatalf("snapshot has no compiled contracts")
	}

	// Выключенный профиль контракта не получает: компилировать нечего, и
	// требовать от него исправной спеки значило бы запретить выключение
	// сломанного контракта.
	if _, ok := set.Contract("default"); ok {
		t.Errorf("profile default is off and must not have a contract")
	}

	if _, ok := set.Contract("api"); !ok {
		t.Errorf("profile api has no compiled contract")
	}
}

type call struct {
	name    string
	profile string
	phase   string
	method  string
	uri     string
	query   string
	body    string
	ctype   string
	status  int

	truncated   bool
	unavailable string

	// Кадрирование фазы frame; nil -- сообщение без секции stream.
	stream *protocol.Stream

	want        string // исход
	wantVerdict string
}

func TestRequestPhase(t *testing.T) {
	cases := []call{
		{
			name: "валидный заказ", profile: "api", method: "POST", uri: "/json/orders",
			body: `{"id":1,"item":"boots","qty":2}`, ctype: "application/json",
			want: decide.OutcomeOK, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "строка вместо числа", profile: "api", method: "POST", uri: "/json/orders",
			body: `{"id":"one","item":"boots"}`, ctype: "application/json",
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "нет обязательного поля", profile: "api", method: "POST", uri: "/json/orders",
			body: `{"id":1}`, ctype: "application/json",
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "лишнее поле", profile: "api", method: "POST", uri: "/json/orders",
			body: `{"id":1,"item":"boots","colour":"red"}`, ctype: "application/json",
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "не JSON вовсе", profile: "api", method: "POST", uri: "/json/orders",
			body: `{"id":1,`, ctype: "application/json",
			want: decide.OutcomeUnparsable, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "усечённое тело", profile: "api", method: "POST", uri: "/json/orders",
			body: `{"id":1,"item":"bo`, ctype: "application/json", truncated: true,
			want: decide.OutcomeTruncated, wantVerdict: protocol.VerdictDeny,
		},
		{
			// Тот же запрос на мягком профиле: непроверяемое проходит.
			name: "усечённое тело, мягкий профиль", profile: "soft", method: "POST",
			uri: "/json-soft/orders", body: `{"id":1,"item":"bo`, ctype: "application/json",
			truncated: true,
			want:      decide.OutcomeTruncated, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "параметр пути не число", profile: "api", method: "GET", uri: "/json/orders/abc",
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "параметр строки запроса не boolean", profile: "api", method: "GET",
			uri: "/json/orders/7", query: "verbose=maybe",
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "путь вне спеки: api пропускает", profile: "api", method: "GET",
			uri:  "/json/nothing-here",
			want: decide.OutcomeUnknownOperation, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "путь вне спеки: strict отказывает", profile: "strict", method: "GET",
			uri:  "/json-strict/nothing-here",
			want: decide.OutcomeUnknownOperation, wantVerdict: protocol.VerdictDeny,
		},
		{
			// observe считает вердикт как enforce, а наружу отдаёт allow.
			name: "наблюдение не блокирует", profile: "observe", method: "POST",
			uri: "/json-observe/orders", body: `{"id":"one"}`, ctype: "application/json",
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "обменник не отдал тело", profile: "api", method: "POST", uri: "/json/orders",
			unavailable: "store_error",
			want:        decide.OutcomeBodyUnavailable, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "проба: путь вне привязок", profile: "_probe", method: "GET",
			uri:  "/healthcheck",
			want: decide.OutcomeUnknownOperation, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "проба: связанный путь и валидное тело", profile: "_probe", method: "POST",
			uri: "/_probe/valid", body: `{"probe":true}`, ctype: "application/json",
			want: decide.OutcomeOK, wantVerdict: protocol.VerdictAllow,
		},
	}

	run(t, cases)
}

func TestResponsePhase(t *testing.T) {
	cases := []call{
		{
			name: "эхо совпало с объявленным ответом", profile: "api",
			phase: protocol.PhaseResponse, method: "POST", uri: "/json/orders", status: 200,
			ctype: "application/json",
			body: `{"method":"POST","url":"/echo","headers":[["host","x"]],` +
				`"body":{"base64":"","bytes":0,"truncated":false}}`,
			want: decide.OutcomeOK, wantVerdict: protocol.VerdictAllow,
		},
		{
			// Приложение отдаёт конверт эха, а спека объявляет отчёт: расхождение
			// приложения со спекой, и на api оно скорится.
			name: "ответ не по спеке", profile: "api", phase: protocol.PhaseResponse,
			method: "GET", uri: "/json/report", status: 200, ctype: "application/json",
			body: `{"method":"GET","url":"/echo","headers":[],` +
				`"body":{"base64":"","bytes":0,"truncated":false}}`,
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictScore,
		},
		{
			name: "тот же ответ на строгом профиле", profile: "strict",
			phase: protocol.PhaseResponse, method: "GET", uri: "/json-strict/report",
			status: 200, ctype: "application/json",
			body: `{"method":"GET","url":"/echo","headers":[],` +
				`"body":{"base64":"","bytes":0,"truncated":false}}`,
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "код ответа не описан", profile: "api", phase: protocol.PhaseResponse,
			method: "POST", uri: "/json/orders", status: 503, ctype: "application/json",
			body: `{"error":"upstream"}`,
			want: decide.OutcomeStatus, wantVerdict: protocol.VerdictScore,
		},
		{
			// Страница приложения -- не наш документ: фильтр типов снимает
			// проверку до всего остального.
			name: "не JSON: тип отфильтрован", profile: "api", phase: protocol.PhaseResponse,
			method: "GET", uri: "/json/report", status: 200, ctype: "text/html",
			body: "<html><body>hi</body></html>",
			want: decide.OutcomeOK, wantVerdict: protocol.VerdictAllow,
		},
		{
			// Ответ крупнее предела приезжает префиксом: проверять префикс JSON
			// нельзя, а политика ответа -- пропускать.
			name: "усечённый ответ", profile: "api", phase: protocol.PhaseResponse,
			method: "POST", uri: "/json/orders", status: 200, ctype: "application/json",
			body: `{"method":"POST","url":"/ec`, truncated: true,
			want: decide.OutcomeTruncated, wantVerdict: protocol.VerdictAllow,
		},
	}

	run(t, cases)
}

func run(t *testing.T, cases []call) {
	t.Helper()

	snap := load(t)

	set, ok := snap.Compiled().(*schema.Set)
	if !ok {
		t.Fatalf("snapshot has no compiled contracts")
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ok := snap.Profile(c.profile)
			if !ok {
				t.Fatalf("profile %q is missing", c.profile)
			}

			contract, ok := set.Contract(c.profile)
			if !ok {
				t.Fatalf("profile %q has no contract", c.profile)
			}

			phase := c.phase
			if phase == "" {
				phase = protocol.PhaseRequest
			}

			req := &protocol.Request{
				V:         protocol.Version,
				RID:       "test",
				Phase:     phase,
				Inspector: "json",
				HTTP: protocol.HTTP{
					Method:   c.method,
					Scheme:   "http",
					Host:     "stand.local",
					URI:      c.uri,
					ArgsSize: int64(len(c.query)),
				},
				Needs: []string{protocol.NeedHeaders, protocol.NeedArgs, protocol.NeedBody},
				Route: protocol.Route{Profile: c.profile},
			}

			if phase == protocol.PhaseResponse {
				req.Response = &protocol.Response{Status: c.status}
			}

			if phase == protocol.PhaseFrame {
				req.ConnID = "conn-test"
				req.Seq = 1
				req.Stream = c.stream
			}

			in := validate.Input{
				Req:      req,
				Profile:  p,
				Contract: contract,
				Headers:  headers(c.ctype),
				Body: body.Body{
					Data:        []byte(c.body),
					Truncated:   c.truncated,
					Unavailable: c.unavailable,
				},
				Args: body.Body{Data: []byte(c.query)},
			}

			out := validate.Run(in)

			if out.Outcome != c.want {
				t.Errorf("outcome = %q, want %q (findings: %s)",
					out.Outcome, c.want, evidence(out))
			}

			d := decide.From(policy(p, req), out.Outcome)

			if d.Verdict != c.wantVerdict {
				t.Errorf("verdict = %q, want %q (outcome %q, code %q)",
					d.Verdict, c.wantVerdict, out.Outcome, d.Code)
			}
		})
	}
}

func policy(p *config.Profile, req *protocol.Request) decide.Phase {
	switch req.Phase {
	case protocol.PhaseResponse:
		return decide.ResponsePhase(p)

	case protocol.PhaseFrame:
		return decide.FramePhase(p, validate.Direction(req))
	}

	return decide.RequestPhase(p)
}

/*
 * Кадры: профиль ws поставки -- чат с двумя типами сообщений. Сообщение
 * клиента судится по схеме своего типа, не описанное -- отказ (контракт как
 * белый список), двоичный кадр -- отказ по опкоду, а та же выдача приложения
 * контрактом не описана и по политике s2c проходит.
 */
func TestFramePhase(t *testing.T) {
	c2s := func(opcode string) *protocol.Stream {
		return &protocol.Stream{Protocol: "websocket", Direction: "c2s", Opcode: opcode,
			Fin: true, Subprotocol: "chat.v2"}
	}

	cases := []call{
		{
			name: "сообщение по схеме", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", stream: c2s("text"),
			body: `{"type":"msg","text":"привет"}`,
			want: decide.OutcomeOK, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "нет обязательного поля", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", stream: c2s("text"), body: `{"type":"msg"}`,
			want: decide.OutcomeMismatch, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "тип сообщения не описан", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", stream: c2s("text"), body: `{"q":"1' OR 1=1-- "}`,
			want: decide.OutcomeUnknownOperation, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "фрагмент без сборки не разбирается", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", stream: c2s("text"), body: `{"type":"msg",`,
			want: decide.OutcomeUnparsable, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "двоичный кадр", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", stream: c2s("binary"), body: "\x00\x01\xfe",
			want: decide.OutcomeOpcode, wantVerdict: protocol.VerdictDeny,
		},
		{
			name: "без секции stream судится как текст c2s", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", body: `{"type":"join","room":"lobby"}`,
			want: decide.OutcomeOK, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "выдача приложения не описана: s2c пропускает", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", body: `{"type":"msg","text":"hi"}`,
			stream: &protocol.Stream{Direction: "s2c", Opcode: "text"},
			want:   decide.OutcomeUnknownOperation, wantVerdict: protocol.VerdictAllow,
		},
		{
			name: "обменник не отдал кадр", profile: "ws", phase: protocol.PhaseFrame,
			method: "GET", uri: "/ws/chat", stream: c2s("text"), unavailable: "store_error",
			want: decide.OutcomeBodyUnavailable, wantVerdict: protocol.VerdictAllow,
		},
	}

	run(t, cases)
}

func headers(contentType string) []protocol.Header {
	if contentType == "" {
		return nil
	}

	return []protocol.Header{{"content-type", contentType}}
}

func evidence(out validate.Outcome) string {
	parts := make([]string, 0, len(out.Findings))

	for _, f := range out.Findings {
		parts = append(parts, f.Code+" "+f.Evidence)
	}

	return strings.Join(parts, "; ")
}

/*
 * Счёт у каждого исхода свой. Профиль soft называет 60 за расхождение со
 * схемой и 20 за вызов, которого нет в контракте: это разные новости, и
 * складываться в сумму фазы они обязаны по-разному. Общий счёт на фазу такую
 * настройку выразить не мог -- ради этого политика и стала парой.
 */
func TestScoreIsPerOutcome(t *testing.T) {
	snap := load(t)

	p, ok := snap.Profile("soft")
	if !ok {
		t.Fatalf("profile soft is missing")
	}

	phase := decide.RequestPhase(p)

	mismatch := decide.From(phase, decide.OutcomeMismatch)
	unknown := decide.From(phase, decide.OutcomeUnknownOperation)

	if mismatch.Verdict != protocol.VerdictScore || mismatch.Score != 60 {
		t.Errorf("mismatch = %s/%d, want score/60", mismatch.Verdict, mismatch.Score)
	}

	if unknown.Verdict != protocol.VerdictScore || unknown.Score != 20 {
		t.Errorf("unknown operation = %s/%d, want score/20", unknown.Verdict, unknown.Score)
	}

	// Тот же исход на другом профиле весит своё: api за него отказывает.
	api, _ := snap.Profile("api")

	if d := decide.From(decide.RequestPhase(api), decide.OutcomeMismatch); d.Verdict != protocol.VerdictDeny {
		t.Errorf("api mismatch = %s, want deny", d.Verdict)
	}
}
