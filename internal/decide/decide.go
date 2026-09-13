/*
 * Политика: исход проверки -> вердикт.
 *
 * Чистая функция от профиля и исхода, без ввода-вывода и без знания о том,
 * откуда взялось тело. Здесь же живёт единственное место, где применяется
 * mode: observe -- вердикт считается как обычно, а модулю уходит allow с
 * пометкой, что решил бы enforce; инициаторы при этом стреляют по решению
 * enforce. Без этого калибровать профиль на живом трафике нечем.
 *
 * Коды причин перечислены здесь целиком, а не рассыпаны по обработчику: набор
 * кодов -- это интерфейс инспектора наружу, по нему строят исключения и
 * читают аудит.
 */

package decide

import (
	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/overload"
	"github.com/exemt/placitum-json/internal/protocol"
	"github.com/exemt/placitum-json/internal/schema"
)

// Коды причин. Все начинаются с JSON_, чтобы в аудите их было видно отдельно
// от кодов других инспекторов.
const (
	CodeMismatch         = "JSON_SCHEMA_MISMATCH"
	CodeUnparsable       = "JSON_UNPARSABLE"
	CodeTruncated        = "JSON_BODY_TRUNCATED"
	CodeTooLarge         = "JSON_BODY_TOO_LARGE"
	CodeTooDeep          = "JSON_TOO_DEEP"
	CodeUnknownOperation = "JSON_UNKNOWN_OPERATION"
	CodeContentType      = "JSON_CONTENT_TYPE"
	CodeStatus           = "JSON_STATUS_UNDECLARED"
	CodeBodyUnavailable  = "JSON_BODY_UNAVAILABLE"
	CodeArgsUnavailable  = "JSON_ARGS_UNAVAILABLE"
	// CodeFrameOpcode -- двоичный кадр там, где контракт описывает текст.
	CodeFrameOpcode = "JSON_FRAME_OPCODE"

	// CodeObserve -- профиль в наблюдении: политика решила не allow, а модулю
	// ушёл allow. Что решила -- в would_* записи аудита.
	CodeObserve = "JSON_OBSERVE"

	// Не подчиняются политике: расхождение конфигурации и перегрузка -- это не
	// свойства запроса, и профиль о них ничего сказать не может.
	CodeUnknownProfile    = "JSON_UNKNOWN_PROFILE"
	CodeSkipped           = "JSON_SKIPPED"
	CodePhaseNotSupported = "JSON_PHASE_NOT_SUPPORTED"
	CodePhaseDisabled     = "JSON_PHASE_DISABLED"
	CodeProfileOff        = "JSON_PROFILE_OFF"
	CodeInternalError     = "JSON_INTERNAL_ERROR"
	// CodeStoreUnavailable -- объект лежал в обменнике, а мы его не взяли.
	// Отдельно от CodeBodyUnavailable: тот описывает тело, которого не дал
	// маршрут, и подчиняется политике профиля.
	CodeStoreUnavailable = "JSON_STORE_UNAVAILABLE"
	// CodeGeoUnavailable -- инициатор пишет в набор подсеть или систему
	// (write: net | net_all | asn), а кодер гео молчит: записи не будет, и
	// молча пропускать её нельзя -- решает waf_exception маршрута.
	CodeGeoUnavailable     = "JSON_GEO_UNAVAILABLE"
	CodeMalformedRequest   = "JSON_MALFORMED_REQUEST"
	CodeUnsupportedVersion = "JSON_UNSUPPORTED_VERSION"
)

/*
 * Outcome -- всё, что случилось с телом и проверкой, одним значением. Исходы
 * обменника и разбора добавлены к исходам схемы: политика у них общая, а различать
 * их в двух местах значило бы разъехаться на первом новом исходе.
 */
const (
	OutcomeOK               = schema.OutcomeOK
	OutcomeMismatch         = schema.OutcomeMismatch
	OutcomeUnknownOperation = schema.OutcomeUnknownOperation
	OutcomeContentType      = schema.OutcomeContentType
	OutcomeStatus           = schema.OutcomeStatus

	OutcomeUnparsable      = "unparsable"
	OutcomeTruncated       = "truncated"
	OutcomeTooLarge        = "too_large"
	OutcomeTooDeep         = "too_deep"
	OutcomeBodyUnavailable = "body_unavailable"
	OutcomeArgsUnavailable = "args_unavailable"
	OutcomeOpcode          = "opcode"
)

// Decision -- то, что уходит в ответ, плюс то, что об этом надо записать.
type Decision struct {
	Verdict string
	Score   int
	Code    string
	// DenyResponse -- имя записи каталога waf_deny_response. Заполнено только
	// при deny: код и страницу отдаёт nginx, инспектор называет запись.
	DenyResponse string

	// WouldVerdict непустой означает observe: модулю ушёл allow с кодом
	// CodeObserve, а enforce ответил бы этим. Единственный способ
	// откалибровать профиль, не заперев клиентов.
	WouldVerdict string
	// WouldScore -- счёт, который ушёл бы с этим вердиктом. По нему судят
	// инициаторы: наблюдение глушит только ответ модулю, просьбы соседям и
	// записи в наборы идут как в enforce.
	WouldScore int
	// WouldCode -- повод решения enforce. Едет в аудит и в просьбы соседям:
	// код наблюдения в просьбе никому ничего не сказал бы.
	WouldCode string
}

/*
 * Phase -- политики одной фазы, снятые с профиля. Обе фазы приводятся к одному
 * виду: исход -> правило. Так решение одно и то же для запроса и для ответа, а
 * разницу между ними держит профиль, а не код.
 */
type Phase struct {
	Mode         string
	Rules        map[string]config.Rule
	DenyResponse string
	// Outcomes -- инициаторы по исходу этой фазы: просьбы соседям и записи в
	// живые наборы. Стреляют по решённому вердикту, см. Fire.
	Outcomes []config.Outcome
}

func RequestPhase(p *config.Profile) Phase {
	return Phase{
		Mode:         p.Mode,
		Rules:        rulesOf(p.Request.Policy.Rules()),
		DenyResponse: p.Request.DenyResponse,
		Outcomes:     p.Request.Outcomes,
	}
}

func ResponsePhase(p *config.Profile) Phase {
	return Phase{
		Mode:         p.Mode,
		Rules:        rulesOf(p.Response.Rules()),
		DenyResponse: p.Response.DenyResponse,
		Outcomes:     p.Response.Outcomes,
	}
}

// FramePhase -- политики направления кадра: у c2s и s2c они свои, как у
// запроса и ответа, и решение по ним одно и то же.
func FramePhase(p *config.Profile, direction string) Phase {
	dir := p.Frame.Direction(direction)

	return Phase{
		Mode:         p.Mode,
		Rules:        rulesOf(dir.Policy.Rules()),
		DenyResponse: dir.DenyResponse,
		Outcomes:     dir.Outcomes,
	}
}

func rulesOf(list []config.NamedRule) map[string]config.Rule {
	out := make(map[string]config.Rule, len(list))

	for _, named := range list {
		out[named.Outcome] = named.Rule
	}

	return out
}

// From -- собственно решение. Исход выбирает правило, правило -- вердикт и
// счёт, mode -- показывать его или только записать.
func From(ph Phase, outcome string) Decision {
	if outcome == OutcomeOK {
		return Decision{Verdict: protocol.VerdictAllow}
	}

	key, code := policy(outcome)
	rule := ph.Rules[key]

	d := Decision{Code: code}

	switch rule.Action {
	case config.ActionDeny:
		d.Verdict = protocol.VerdictDeny
		d.DenyResponse = ph.DenyResponse

	case config.ActionScore:
		d.Verdict = protocol.VerdictScore
		d.Score = rule.Score

	default:
		d.Verdict = protocol.VerdictAllow
	}

	/*
	 * observe: модулю всегда allow, а решение остаётся в записи под своим
	 * поводом -- по нему и видно, на чём профиль сработал бы. Код ответа
	 * при этом один на все случаи, чтобы в записи модуля наблюдение было
	 * видно без похода в kind=inspector.
	 */
	if ph.Mode == config.ModeObserve && d.Verdict != protocol.VerdictAllow {
		d.WouldVerdict = d.Verdict
		d.WouldScore = d.Score
		d.WouldCode = d.Code
		d.Verdict = protocol.VerdictAllow
		d.Score = 0
		d.Code = CodeObserve
		d.DenyResponse = ""
	}

	return d
}

/*
 * policy переводит исход проверки в строку таблицы политик и код причины.
 *
 * Две пары исходов делят строку намеренно. Слишком глубокий документ судится
 * как несошедшийся со схемой: и то и другое -- «документ не такой, каким его
 * ждут». Слишком крупное тело -- как усечённое: и там и там мы его не
 * проверяли. Разводить их по отдельным строкам значило бы предлагать оператору
 * настройку, разницу между половинами которой он не сможет объяснить.
 */
func policy(outcome string) (key, code string) {
	switch outcome {
	case OutcomeMismatch:
		return config.OutcomeInvalid, CodeMismatch

	case OutcomeTooDeep:
		return config.OutcomeInvalid, CodeTooDeep

	case OutcomeUnparsable:
		return config.OutcomeUnparsable, CodeUnparsable

	case OutcomeTruncated:
		return config.OutcomeTruncated, CodeTruncated

	case OutcomeTooLarge:
		return config.OutcomeTruncated, CodeTooLarge

	case OutcomeUnknownOperation:
		return config.OutcomeUnknownOperation, CodeUnknownOperation

	case OutcomeContentType:
		return config.OutcomeContentType, CodeContentType

	case OutcomeStatus:
		return config.OutcomeStatus, CodeStatus

	case OutcomeBodyUnavailable:
		return config.OutcomeUnavailable, CodeBodyUnavailable

	case OutcomeArgsUnavailable:
		return config.OutcomeUnavailable, CodeArgsUnavailable

	case OutcomeOpcode:
		return config.OutcomeOpcode, CodeFrameOpcode
	}

	return "", ""
}

/* --- инициаторы по исходу --------------------------------------------------- */

/*
 * Ban -- запись в живой набор: кого (Write) и про какой адрес. Анонсы и
 * состав системы по адресу разворачивает обработчик у кодера, в бюджете
 * сообщения: этот пакет кодера не знает. Публикуется запись после решения --
 * этот запрос уже решён, а набор нужен следующим и соседним нодам.
 */
type Ban struct {
	Dataset string
	// Write -- кого писать: addr, net, net_all, asn.
	Write  string
	Addr   string
	TTL    int
	Reason string
}

// Fired -- что сделали инициаторы: просьбы уезжают в ответе рядом с вердиктом,
// записи публикуются после него, имена -- в запись аудита. Names именуют
// строку по действию, а не по номеру: номер поедет при первой правке таблицы.
type Fired struct {
	Actions []protocol.Action
	Bans    []Ban
	Names   []string
}

/*
 * Fire -- инициаторы фазы по её решению.
 *
 * Сравнивается тот счёт, который уходит модулю: коэффициент соседа уже в нём,
 * иначе оператор смотрел бы на одно число, а сосед двигал другое.
 *
 * Наблюдение глушит только ответ модулю. Инициаторы судят по решению enforce
 * и стреляют как в бою: просьбы соседям и записи в наборы -- разговор
 * инспекторов между собой, а не вердикт, и observe его не прерывает
 * (docs/inspectors.md, «Наблюдение профиля»).
 */
func Fire(ph Phase, d Decision, addr string) Fired {
	if len(ph.Outcomes) == 0 {
		return Fired{}
	}

	verdict, score, code := d.Verdict, d.Score, d.Code

	if d.WouldVerdict != "" {
		verdict, score, code = d.WouldVerdict, d.WouldScore, d.WouldCode
	}

	var out Fired

	for _, o := range ph.Outcomes {
		if !o.Matches(verdict, score) {
			continue
		}

		if o.Asks() {
			out.Actions = append(out.Actions, ask(o, code))
			out.Names = append(out.Names, outcomeName(o))

			continue
		}

		/*
		 * Адреса нет -- писать некого: сообщение пробы приходит без
		 * conn.client_ip. Подсеть и систему по адресу развернёт обработчик.
		 */
		if addr == "" {
			continue
		}

		out.Bans = append(out.Bans, Ban{
			Dataset: o.List,
			Write:   o.Subject(),
			Addr:    addr,
			TTL:     o.TTL.Seconds(),
			Reason:  reason(o, code),
		})

		out.Names = append(out.Names, outcomeName(o))
	}

	return out
}

func ask(o config.Outcome, code string) protocol.Action {
	out := protocol.Action{
		To:      o.To,
		Do:      o.Do,
		Apply:   o.Axis(),
		Phase:   o.Phase,
		Code:    reason(o, code),
		Counter: o.Counter,
		Marker:  o.Marker,
		Group:   o.Group,
		Set:     o.Set,
		Headers: o.Headers,
		Args:    o.Args,
		Body:    o.Body,
	}

	// Срок архива -- только у archive с set on; ноль в YAML значит "как на
	// маршруте", поэтому на провод едет лишь названный.
	if o.Do == protocol.DoArchive && o.Set == "on" && o.TTL.Seconds() > 0 {
		ttl := int64(o.TTL.Seconds())
		out.TTL = &ttl
	}

	// Исход просьбы -- только у archive с set on; пусто значит "любой".
	// Слова проверены на загрузке профиля, здесь остаётся канонический
	// порядок: провод не должен зависеть от порядка слов в файле.
	if o.Do == protocol.DoArchive && o.Set == "on" && len(o.When) > 0 {
		when, _ := protocol.CheckArchiveWhen(o.When)
		out.When = when
	}

	if o.Delta != nil {
		out.Delta = *o.Delta
	}

	if o.Value != nil {
		out.Value = *o.Value
	}

	return out
}

// reason -- повод: свой из строки либо код решения, по которому она сработала.
func reason(o config.Outcome, code string) string {
	if o.Code != "" {
		return o.Code
	}

	return code
}

// outcomeName -- как строка называется в записи аудита: по действию, а не по
// порядковому номеру, -- номер поедет при первой правке таблицы.
func outcomeName(o config.Outcome) string {
	if o.Asks() {
		return o.Do
	}

	return o.List
}

/*
 * FireOverload -- строки перегрузки секции запроса: fill -- заполнение очереди
 * при постановке запроса, shed -- запрос снят по полной очереди
 * (internal/overload). code -- повод строки, у которой свой не назван.
 * Сравнивать с решением нечего: у строки перегрузки его нет.
 */
func FireOverload(outcomes []config.Outcome, fill int, shed bool, addr, code string) Fired {
	var out Fired

	for _, o := range outcomes {
		if o.On != config.OnOverload || !overload.Fires(overload.At(o.At), fill, shed) {
			continue
		}

		if o.Asks() {
			out.Actions = append(out.Actions, ask(o, code))
			out.Names = append(out.Names, outcomeName(o))

			continue
		}

		// Адреса нет -- писать некого; подсеть и систему развернёт обработчик.
		if addr == "" {
			continue
		}

		out.Bans = append(out.Bans, Ban{
			Dataset: o.List,
			Write:   o.Subject(),
			Addr:    addr,
			TTL:     o.TTL.Seconds(),
			Reason:  reason(o, code),
		})

		out.Names = append(out.Names, outcomeName(o))
	}

	return out
}
