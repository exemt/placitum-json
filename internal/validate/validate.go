/*
 * Порядок проверки одного сообщения: что смотрим, в какой очерёдности и когда
 * останавливаемся.
 *
 * Порядок здесь -- содержательное решение, а не оформление. Сначала выясняется,
 * есть ли у нас документ целиком: недоступное, усечённое или слишком крупное
 * тело проверкой не является, и делать вид, что мы его проверили, нельзя.
 * Только потом документ разбирается, и только потом сверяется со схемой.
 *
 * Отдельно от схемы стоит вопрос «а точно ли нам всё показали». Строка запроса
 * может не сниматься маршрутом, и тогда проверка параметров не «прошла», а не
 * состоялась. Это свой исход, и он не должен прятать нарушение схемы -- поэтому
 * запоминается и применяется только если остальное сошлось.
 */

package validate

import (
	"errors"
	"strings"

	"github.com/exemt/placitum-json/internal/audit"
	"github.com/exemt/placitum-json/internal/body"
	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/decide"
	"github.com/exemt/placitum-json/internal/protocol"
	"github.com/exemt/placitum-json/internal/schema"
)

// Input -- всё, что собрал обработчик: сообщение и объекты обменника.
type Input struct {
	Req      *protocol.Request
	Profile  *config.Profile
	Contract *schema.Contract

	Body    body.Body
	Args    body.Body
	Headers []protocol.Header
}

// Outcome -- исход проверки и то, чем его объяснить.
type Outcome struct {
	Outcome   string
	Operation string
	Findings  []audit.Finding
	Errors    int

	// Skipped непустой означает, что проверка не выполнялась и это штатно:
	// тело не того типа, тела нет вовсе, проверок не включено.
	Skipped string

	// Fault непустой означает, что проверка не состоялась по нашей вине:
	// обменник не отдал объект, который лежал. Политике профиля такой исход
	// не подчиняется -- он вообще не про запрос, и отвечают на него вердиктом
	// error. Недоступность, о которой сказал модуль, сюда не попадает: ею уже
	// распорядился маршрут классом body у waf_exception.
	Fault string
}

func Run(in Input) Outcome {
	switch in.Req.Phase {
	case protocol.PhaseResponse:
		return responsePhase(in)

	case protocol.PhaseFrame:
		return framePhase(in)
	}

	return requestPhase(in)
}

/*
 * Кадр: опкод до всего остального -- двоичное сообщение там, где контракт
 * про текст, не разбирается и не сверяется, это свой исход. Дальше та же
 * лестница, что у запроса: документ целиком? разбирается? сходится?
 */
func framePhase(in Input) Outcome {
	p := in.Profile
	direction := Direction(in.Req)
	dir := p.Frame.Direction(direction)

	if !dir.Checks.Body {
		return Outcome{Outcome: decide.OutcomeOK, Skipped: "body_check_off"}
	}

	if Opcode(in.Req) == config.OpcodeBinary {
		return Outcome{
			Outcome: decide.OutcomeOpcode,
			Errors:  1,
			Findings: []audit.Finding{finding("json-frame-binary", audit.SeverityMedium,
				"a binary frame where the contract describes text messages")},
		}
	}

	if out, stop := bodyState(in.Body, p.Limits); stop {
		return out
	}

	res := in.Contract.Frame(&schema.FrameInput{
		Path:        pathOf(in.Req.HTTP.URI),
		Direction:   direction,
		Subprotocol: Subprotocol(in.Req),
		Body:        in.Body.Data,
	}, dir.Checks, options(p))

	return merge(res, "")
}

// Direction -- сторона кадра из сообщения модуля; без секции stream -- c2s,
// сторона, которую модуль ведёт первой.
func Direction(req *protocol.Request) string {
	if req.Stream == nil || req.Stream.Direction == "" {
		return config.DirectionC2S
	}

	return req.Stream.Direction
}

// Opcode -- опкод кадра; без секции stream читается как текст.
func Opcode(req *protocol.Request) string {
	if req.Stream == nil || req.Stream.Opcode == "" {
		return config.OpcodeText
	}

	return req.Stream.Opcode
}

func Subprotocol(req *protocol.Request) string {
	if req.Stream == nil {
		return ""
	}

	return req.Stream.Subprotocol
}

func requestPhase(in Input) Outcome {
	p := in.Profile
	checks := p.Request.Checks

	if checks.Body {
		if out, stop := bodyState(in.Body, p.Limits); stop {
			return out
		}
	}

	/*
	 * Строка запроса: её может не быть в waf_capture маршрута. Пустая строка и
	 * неснятая строка выглядят в обменнике одинаково, поэтому спрашиваем длину --
	 * она приезжает инлайном именно для этого.
	 */
	deferred := ""

	fault := ""

	if checks.Query && in.Req.HTTP.ArgsSize > 0 &&
		(!in.Args.Available() || !in.Req.Needed(protocol.NeedArgs)) {
		/*
		 * Строка была, но её нам не показали: маршрут не снимает args либо
		 * обменник не отдал объект. Проверка параметров при этом не «прошла» --
		 * она не состоялась, и говорить о ней надо отдельно.
		 *
		 * Второе -- уже наш сбой: строка лежала, и не прочли её мы.
		 */
		deferred = decide.OutcomeArgsUnavailable

		if in.Args.Failed() {
			fault = in.Args.Unavailable
		}
	}

	res := in.Contract.Request(&schema.Input{
		Method:  in.Req.HTTP.Method,
		Scheme:  in.Req.HTTP.Scheme,
		Host:    in.Req.HTTP.Host,
		Path:    pathOf(in.Req.HTTP.URI),
		Query:   string(in.Args.Data),
		Headers: headers(in.Headers),
		Body:    in.Body.Data,
	}, checks, options(p))

	out := merge(res, deferred)
	out.Fault = fault

	return out
}

func responsePhase(in Input) Outcome {
	p := in.Profile
	checks := p.Response.Checks

	contentType := headerValue(in.Headers, "content-type")

	/*
	 * Фильтр типов стоит до всего остального: тело text/html -- это не
	 * нарушение контракта и не «не сошлось со схемой», это просто не наш
	 * документ. Разбирать его как JSON значит выдавать ошибку разбора на
	 * каждой странице приложения.
	 */
	if len(in.Body.Data) > 0 && !p.Response.TypeAllowed(contentType) {
		return Outcome{Outcome: decide.OutcomeOK, Skipped: "content_type_filtered"}
	}

	if checks.Body {
		if out, stop := bodyState(in.Body, p.Limits); stop {
			return out
		}
	}

	res := in.Contract.Response(&schema.Input{
		Method:  in.Req.HTTP.Method,
		Scheme:  in.Req.HTTP.Scheme,
		Host:    in.Req.HTTP.Host,
		Path:    pathOf(in.Req.HTTP.URI),
		Headers: headers(in.Headers),
		Body:    in.Body.Data,
		Status:  status(in.Req),
	}, checks, options(p))

	return merge(res, "")
}

/*
 * bodyState -- «есть ли у нас документ целиком». Второе значение говорит,
 * прекращать ли на этом: во всех этих исходах сверять со схемой нечего.
 *
 * Усечённое тело не валидируется никогда. JSON -- не поток: у документа есть
 * закрывающая скобка, и префикс невалиден всегда. Схема на нём дала бы
 * «unexpected end of input» на любом теле, то есть отказ по причине, которая
 * не имеет отношения к содержимому.
 */
func bodyState(b body.Body, limits config.Limits) (Outcome, bool) {
	if !b.Available() {
		out := Outcome{
			Outcome:  decide.OutcomeBodyUnavailable,
			Errors:   1,
			Findings: []audit.Finding{finding("json-body-unavailable", audit.SeverityInfo, b.Unavailable)},
		}

		// Тело лежало, а мы его не взяли: судить об этом запросе нечем.
		if b.Failed() {
			out.Fault = b.Unavailable
		}

		return out, true
	}

	if b.Truncated {
		return Outcome{
			Outcome: decide.OutcomeTruncated,
			Errors:  1,
			Findings: []audit.Finding{finding("json-body-truncated", audit.SeverityMedium,
				"the body is a prefix: a truncated document cannot be validated")},
		}, true
	}

	if len(b.Data) == 0 {
		// Пустое тело -- не исход: операция может его и не требовать, а если
		// требует, это заметит проверка по схеме.
		return Outcome{}, false
	}

	if limits.MaxBody > 0 && int64(len(b.Data)) > limits.MaxBody.Bytes() {
		return Outcome{
			Outcome: decide.OutcomeTooLarge,
			Errors:  1,
			Findings: []audit.Finding{finding("json-body-too-large", audit.SeverityMedium,
				"the body is larger than limits.max_body")},
		}, true
	}

	if err := schema.Scan(b.Data, limits.MaxDepth); err != nil {
		if errors.Is(err, schema.ErrTooDeep) {
			return Outcome{
				Outcome: decide.OutcomeTooDeep,
				Errors:  1,
				Findings: []audit.Finding{finding("json-too-deep", audit.SeverityHigh,
					"the document is deeper than limits.max_depth")},
			}, true
		}

		return Outcome{
			Outcome:  decide.OutcomeUnparsable,
			Errors:   1,
			Findings: []audit.Finding{finding("json-unparsable", audit.SeverityMedium, err.Error())},
		}, true
	}

	return Outcome{}, false
}

// merge превращает результат схемы в исход и применяет отложенный: тот
// показывается только тогда, когда со схемой всё сошлось.
// merge складывает исход схемы с отложенным. Fault сюда не приходит: наш сбой
// не смешивается с исходом проверки, его ставит вызывающий.
func merge(res schema.Result, deferred string) Outcome {
	out := Outcome{
		Outcome:   res.Outcome,
		Operation: res.Operation,
		Findings:  res.Findings,
		Errors:    res.Errors,
	}

	if out.Outcome == decide.OutcomeOK && deferred != "" {
		out.Outcome = deferred
		out.Errors = 1
		out.Findings = append(out.Findings, finding("json-args-unavailable",
			audit.SeverityInfo, "the query string is not captured on this route"))
	}

	return out
}

func options(p *config.Profile) schema.Options {
	return schema.Options{
		MaxErrors:  p.Limits.MaxErrors,
		Paths:      p.Audit.Paths,
		HashValues: p.Audit.Values == config.AuditValuesHash,
	}
}

func headers(in []protocol.Header) []schema.Header {
	out := make([]schema.Header, 0, len(in))

	for _, h := range in {
		out = append(out, schema.Header{h.Name(), h.Value()})
	}

	return out
}

func headerValue(in []protocol.Header, name string) string {
	for _, h := range in {
		if strings.EqualFold(h.Name(), name) {
			return h.Value()
		}
	}

	return ""
}

// pathOf отрезает строку запроса, если модуль прислал её в URI: параметры
// проверяются отдельно и в сопоставлении пути не участвуют.
func pathOf(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}

	return uri
}

func status(req *protocol.Request) int {
	if req.Response == nil {
		return 0
	}

	return req.Response.Status
}

func finding(code, severity, text string) audit.Finding {
	return audit.Finding{
		Code:     code,
		Severity: severity,
		Target:   audit.TargetBody,
		Evidence: text,
	}
}
