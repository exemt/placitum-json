/*
 * Профиль инспектора контракта: тот самый отдельный конфиг, который задаёт
 * оператор.
 *
 * Профиль выбирается тегом profile= записи waf_inspector и приезжает в
 * route.profile -- тем же механизмом, что у ip, modsec и капчи. Один процесс
 * обслуживает сколько угодно профилей: разным маршрутам -- разные контракты.
 *
 * Две фазы описаны двумя секциями и независимы: у каждой свой набор проверок и
 * свои политики. Связывать их нечем и незачем -- операция спеки находится по
 * методу и пути, а они приезжают в каждом сообщении, см.
 * docs/README.md#почему-фазы-не-связаны.
 *
 * Всё, что можно проверить при загрузке, проверяется здесь: профиль с опечаткой
 * обязан не подняться, а не пропустить трафик мимо проверки на первом запросе.
 */

package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-json/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"

	// Чем описан контракт. openapi -- документ целиком, из него берётся
	// операция; jsonschema -- схема тела, а какую применять, решает bindings.
	KindOpenAPI    = "openapi"
	KindJSONSchema = "jsonschema"

	// Словарь политик один на все исходы: третьего значения нет, и это
	// сознательно -- каждый исход обязан читаться как вердикт.
	ActionDeny  = "deny"
	ActionScore = "score"
	ActionAllow = "allow"

	MatchExact  = "exact"
	MatchPrefix = "prefix"

	// Триггеры инициаторов: собственный решённый вердикт фазы. Строки те же,
	// что у действий политики, -- и это не совпадение: инициатор смотрит на
	// решение, а не на его предпосылки.
	OnDeny  = ActionDeny
	OnAllow = ActionAllow
	OnScore = ActionScore

	/*
	 * Кого писать в набор -- те же слова, что у капчи. Адрес меняется дешевле
	 * всего. Подсеть -- уже нет: net -- эффективный анонс, самый узкий (лайт),
	 * net_all -- все анонсы, накрывающие адрес, включая чужие широкие (хард).
	 * Автономная система целиком (asn) -- решение другого масштаба, и потому
	 * это отдельная строка, а не переключатель точности. Во что они
	 * разворачиваются, решает netinfo.Values -- одна на всех отправителей.
	 */
	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"

	// Значения полей в аудите: их нет вовсе либо они уезжают хешем. Открытым
	// текстом -- никогда: тело запроса к API это ровно то место, где лежат
	// пароли и персональные данные, а аудит живёт в ClickHouse месяцами.
	AuditValuesOff  = "off"
	AuditValuesHash = "hash"
)

// DefaultName -- профиль, который применяется, когда маршрут не назвал
// никакого. Его отсутствие -- ошибка старта.
const DefaultName = "default"

// ProbeName -- зарезервированное имя: проба шлёт обычное сообщение с этим
// профилем и заведомо невалидным телом, а ждёт deny. Закрывает вопрос «как
// проверить инспектор, когда на валидном теле он молчит».
const ProbeName = "_probe"

// SchemaFilePrefix -- как документ лежит рядом с profile.yaml. Имя объекта
// содержимого приезжает в профиле, файл называется по нему: два имени у одного
// документа разъехались бы на первом переименовании.
const SchemaFilePrefix = "schema-"

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	methodRe = regexp.MustCompile(`^[A-Z]+$`)
	codeRe   = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
)

/*
 * Size -- размер в человеческой записи ("1m", "512k"). Отдельный тип по той же
 * причине, что Duration у калитки: число байт в файле, который правят руками,
 * читается хуже, чем ошибается.
 */
type Size int64

func (s *Size) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}

	v, err := ParseSize(raw)
	if err != nil {
		return err
	}

	*s = Size(v)

	return nil
}

func (s Size) Bytes() int64 { return int64(s) }

func ParseSize(raw string) (int64, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}

	mult := int64(1)

	switch {
	case strings.HasSuffix(raw, "k"):
		mult, raw = 1<<10, strings.TrimSuffix(raw, "k")
	case strings.HasSuffix(raw, "m"):
		mult, raw = 1<<20, strings.TrimSuffix(raw, "m")
	case strings.HasSuffix(raw, "g"):
		mult, raw = 1<<30, strings.TrimSuffix(raw, "g")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", raw, err)
	}

	if n < 0 {
		return 0, fmt.Errorf("size must not be negative: %q", raw)
	}

	return n * mult, nil
}

/*
 * Duration -- срок записи в живом наборе ("1h", "15m"). Отдельный тип по той
 * же причине, что Size: секунды в файле, который правят руками, читаются хуже,
 * чем ошибаются.
 */
type Duration int

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}

	v, err := ParseDuration(raw)
	if err != nil {
		return err
	}

	*d = Duration(v)

	return nil
}

// Seconds -- срок в секундах: столько его ждёт и событие набора, и контроллер.
func (d Duration) Seconds() int { return int(d) }

func ParseDuration(raw string) (int, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}

	mult := 1

	switch {
	case strings.HasSuffix(raw, "s"):
		raw = strings.TrimSuffix(raw, "s")
	case strings.HasSuffix(raw, "m"):
		mult, raw = 60, strings.TrimSuffix(raw, "m")
	case strings.HasSuffix(raw, "h"):
		mult, raw = 3600, strings.TrimSuffix(raw, "h")
	case strings.HasSuffix(raw, "d"):
		mult, raw = 86400, strings.TrimSuffix(raw, "d")
	}

	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", raw, err)
	}

	if n < 0 {
		return 0, fmt.Errorf("duration must not be negative: %q", raw)
	}

	return n * mult, nil
}

/* --- документ профиля ------------------------------------------------------ */

type Profile struct {
	// Имя -- имя каталога, а не поле файла: два источника истины для одного
	// имени разъезжаются при первом переименовании.
	Name string `yaml:"-"`

	Mode        string `yaml:"mode"`
	Description string `yaml:"description"`

	Schema   Schema        `yaml:"schema"`
	Trigger  Trigger       `yaml:"trigger"`
	Request  RequestPhase  `yaml:"request"`
	Response ResponsePhase `yaml:"response"`
	Frame    FramePhase    `yaml:"frame"`
	Bindings []Binding     `yaml:"bindings"`
	Limits   Limits        `yaml:"limits"`
	Audit    Audit         `yaml:"audit"`

	// Documents -- тексты схем, приехавшие файлами рядом с profile.yaml. Ключ
	// -- имя объекта содержимого (schema.source и bindings[].schema).
	Documents map[string][]byte `yaml:"-"`
}

type Schema struct {
	Kind   string `yaml:"kind"`
	Source string `yaml:"source"`

	/*
	 * BasePath -- что срезать с URI перед сопоставлением с путями спеки: спека
	 * пишется от корня сервиса, а location стоит на префиксе.
	 *
	 * Отдельного переключателя «брать префикс из servers[]» здесь нет и не
	 * будет: префиксы серверов документа маршрутизатор срезает сам, всегда.
	 * Тумблер рядом означал бы, что без него они не срезаются, -- а это
	 * неправда, и настройка, которая лжёт, хуже отсутствующей.
	 */
	BasePath string `yaml:"base_path"`
}

/*
 * Rule -- что делать с исходом и сколько за него добавить.
 *
 * Действие и счёт живут парой намеренно. Раньше счёт был один на фазу, и это
 * означало, что «ответ не по спеке» и «код ответа не описан» весят одинаково,
 * даже когда оператор считает иначе: точечно указать было нечем. Пара на исход
 * убирает вопрос «а сколько баллов добавит вот эта строка» -- ответ стоит
 * рядом с ней.
 *
 * Счёт читается только при action: score. При deny его смотреть незачем --
 * отказ порога не спрашивает, -- а при allow нечего и добавлять.
 */
type Rule struct {
	Action string `yaml:"action"`
	Score  int    `yaml:"score"`
}

/*
 * RequestRules -- исходы фазы запроса, по строке на каждый. Отдельный тип от
 * ответа, а не общий с полем-исключением: `status` в секции запроса обязан
 * быть ошибкой разбора -- кода ответа на этой фазе не бывает.
 */
type RequestRules struct {
	Invalid          Rule `yaml:"invalid"`
	Unparsable       Rule `yaml:"unparsable"`
	Truncated        Rule `yaml:"truncated"`
	UnknownOperation Rule `yaml:"unknown_operation"`
	ContentType      Rule `yaml:"content_type"`
	Unavailable      Rule `yaml:"unavailable"`
}

// ResponseRules -- те же исходы плюс код ответа, которого нет у запроса.
type ResponseRules struct {
	RequestRules `yaml:",inline"`
	Status       Rule `yaml:"status"`
}

type RequestChecks struct {
	Body       bool `yaml:"body"`
	Query      bool `yaml:"query"`
	PathParams bool `yaml:"path_params"`
	// Headers по умолчанию выключены: спеки часто объявляют обязательным то,
	// что на живом трафике ставит край, а не клиент.
	Headers bool `yaml:"headers"`
}

type ResponseChecks struct {
	Body        bool `yaml:"body"`
	Status      bool `yaml:"status"`
	ContentType bool `yaml:"content_type"`
}

// RequestPhase и ResponsePhase -- разные типы, а не один с общим набором
// полей: `status` в секции запроса обязан быть ошибкой разбора, а не молча
// проигнорированным ключом.
type RequestPhase struct {
	Enabled bool          `yaml:"enabled"`
	Checks  RequestChecks `yaml:"checks"`
	Policy  RequestRules  `yaml:"policy"`
	// DenyResponse -- одна запись каталога на фазу: отказ по любому исходу
	// показывает одну и ту же страницу. Клиент видит код, а не исход, и три
	// страницы на три исхода объясняли бы ему то, чего он не спрашивал.
	DenyResponse string `yaml:"deny_response"`
	// Outcomes -- инициаторы по исходу этой фазы: просьба соседу либо запись
	// адреса в живой набор.
	Outcomes []Outcome `yaml:"outcomes"`
}

type ResponsePhase struct {
	Enabled bool           `yaml:"enabled"`
	Checks  ResponseChecks `yaml:"checks"`
	Policy  ResponseRules  `yaml:"policy"`
	// OnlyTypes -- фильтр до всего остального: тело не этого типа инспектор
	// как JSON не разбирает и политик не трогает. Суффикс "+json" покрывает
	// application/problem+json и прочие структурированные типы.
	OnlyTypes    []string  `yaml:"only_types"`
	DenyResponse string    `yaml:"deny_response"`
	Outcomes     []Outcome `yaml:"outcomes"`
}

// Binding -- какую схему применять, когда контракт задан не OpenAPI. Первое
// совпадение выигрывает; пустой список означает «одна схема на всё тело фазы».
type Binding struct {
	Methods []string `yaml:"methods"`
	Path    string   `yaml:"path"`
	Match   string   `yaml:"match"`
	Schema  string   `yaml:"schema"`
}

/*
 * Фаза кадров: третья независимая проверка рядом с запросом и ответом
 * (docs/README.md, «Кадры WebSocket»). У сокета нет ни
 * метода, ни операции, поэтому схема выбирается не по вызову, а по
 * направлению и по типу сообщения -- дискриминатору в теле. Политики свои у
 * каждого направления: отказ на c2s -- Close до приложения, отказ на s2c рвёт
 * живую сессию, и цена ошибки у них разная, как у запроса и ответа.
 */
type FramePhase struct {
	Enabled  bool           `yaml:"enabled"`
	Bindings []FrameBinding `yaml:"bindings"`
	C2S      FrameDirection `yaml:"c2s"`
	S2C      FrameDirection `yaml:"s2c"`
}

/*
 * FrameBinding -- какую схему применять к сообщению. Путь сравнивается с URI
 * рукопожатия, направление и подпротокол -- с кадрированием из сообщения,
 * дискриминатор -- со значением поля в теле. Первое совпадение выигрывает.
 */
type FrameBinding struct {
	Path          string         `yaml:"path"`
	Match         string         `yaml:"match"`
	Direction     string         `yaml:"direction"`
	Subprotocol   string         `yaml:"subprotocol"`
	Discriminator *Discriminator `yaml:"discriminator"`
	Schema        string         `yaml:"schema"`
}

// Discriminator -- «поле такое-то равно тому-то»: JSON pointer и значение
// строкой. Числа и булевы сравниваются своей записью: 1 -- "1", true -- "true".
type Discriminator struct {
	Pointer string `yaml:"pointer"`
	Value   string `yaml:"value"`
}

type FrameChecks struct {
	Body bool `yaml:"body"`
}

/*
 * FrameRules -- исходы направления. Те же, что у запроса, кроме одного:
 * вместо типа содержимого -- опкод. Двоичный кадр там, где контракт про
 * текст, -- это «не наш документ», а не «не сошлось со схемой».
 */
type FrameRules struct {
	Invalid          Rule `yaml:"invalid"`
	Unparsable       Rule `yaml:"unparsable"`
	Truncated        Rule `yaml:"truncated"`
	UnknownOperation Rule `yaml:"unknown_operation"`
	Opcode           Rule `yaml:"opcode"`
	Unavailable      Rule `yaml:"unavailable"`
}

type FrameDirection struct {
	Checks       FrameChecks `yaml:"checks"`
	Policy       FrameRules  `yaml:"policy"`
	DenyResponse string      `yaml:"deny_response"`
	Outcomes     []Outcome   `yaml:"outcomes"`
}

// Направления кадра, как их называет модуль в stream.direction.
const (
	DirectionC2S = "c2s"
	DirectionS2C = "s2c"
	DirectionAny = "any"
)

// Опкоды, как их называет модуль в stream.opcode. Продолжение судится как
// текст: опкод сообщения без состояния по соединению неизвестен.
const (
	OpcodeText         = "text"
	OpcodeBinary       = "binary"
	OpcodeContinuation = "continuation"
)

/*
 * Limits -- свойство процесса, а не профиля. Объявляется в профиле, потому что
 * там его ищут; расхождение между профилями отвергает поколение целиком -- как
 * roster у калитки.
 */
type Limits struct {
	MaxBody   Size `yaml:"max_body"`
	MaxDepth  int  `yaml:"max_depth"`
	MaxErrors int  `yaml:"max_errors"`
	Cache     int  `yaml:"cache"`
}

type Audit struct {
	Values string `yaml:"values"`
	Paths  bool   `yaml:"paths"`
}

/* --- умолчания и разбор ---------------------------------------------------- */

/*
 * Умолчания фаз разные, и это главное решение файла. Цена ошибки на фазах
 * несимметрична: отказ на запросе не пускает мусор, отказ на ответе ломает
 * витрину после того, как приложение уже отработало. Поэтому запрос по
 * умолчанию гейтит, ответ -- скорит.
 */
func defaults(name string) *Profile {
	// Умолчание счёта: применяется, когда исход перевели на score, а числа не
	// назвали. Разное у фаз по той же причине, что и действия.
	deny := func() Rule { return Rule{Action: ActionDeny, Score: 70} }
	allowReq := func() Rule { return Rule{Action: ActionAllow, Score: 70} }
	allowRsp := func() Rule { return Rule{Action: ActionAllow, Score: 40} }
	scoreRsp := func() Rule { return Rule{Action: ActionScore, Score: 40} }

	return &Profile{
		Name: name,
		Mode: ModeEnforce,
		Schema: Schema{
			Kind: KindOpenAPI,
		},
		Request: RequestPhase{
			Enabled: true,
			Checks: RequestChecks{
				Body:       true,
				Query:      true,
				PathParams: true,
				Headers:    false,
			},
			Policy: RequestRules{
				Invalid:          deny(),
				Unparsable:       deny(),
				Truncated:        deny(),
				UnknownOperation: allowReq(),
				ContentType:      allowReq(),
				Unavailable:      allowReq(),
			},
			DenyResponse: "json_invalid",
		},
		Response: ResponsePhase{
			Enabled: true,
			Checks: ResponseChecks{
				Body:        true,
				Status:      true,
				ContentType: true,
			},
			Policy: ResponseRules{
				RequestRules: RequestRules{
					Invalid:          scoreRsp(),
					Unparsable:       allowRsp(),
					Truncated:        allowRsp(),
					UnknownOperation: allowRsp(),
					ContentType:      allowRsp(),
					Unavailable:      allowRsp(),
				},
				Status: scoreRsp(),
			},
			OnlyTypes:    []string{"application/json", "+json"},
			DenyResponse: "json_response_invalid",
		},
		/*
		 * Кадры выключены, пока профиль их не включит: у обычного API сокетов
		 * нет. Умолчания направлений повторяют пару запрос/ответ: c2s гейтит
		 * -- контракт как белый список сообщений, -- s2c скорит.
		 */
		Frame: FramePhase{
			Enabled: false,
			C2S: FrameDirection{
				Checks: FrameChecks{Body: true},
				Policy: FrameRules{
					Invalid:          deny(),
					Unparsable:       deny(),
					Truncated:        deny(),
					UnknownOperation: deny(),
					Opcode:           deny(),
					Unavailable:      allowReq(),
				},
				DenyResponse: "ws_policy",
			},
			S2C: FrameDirection{
				Checks: FrameChecks{Body: true},
				Policy: FrameRules{
					Invalid:          scoreRsp(),
					Unparsable:       allowRsp(),
					Truncated:        allowRsp(),
					UnknownOperation: allowRsp(),
					Opcode:           allowRsp(),
					Unavailable:      allowRsp(),
				},
				DenyResponse: "ws_policy",
			},
		},
		Limits: Limits{
			MaxBody:   Size(1 << 20),
			MaxDepth:  64,
			MaxErrors: 20,
			Cache:     4096,
		},
		Audit: Audit{
			Values: AuditValuesOff,
			Paths:  true,
		},
	}
}

// ParseProfile разбирает profile.yaml поверх умолчаний. Схемы подключаются
// отдельно: они лежат рядом файлами и перечитываются вместе с профилем.
func ParseProfile(name string, raw []byte) (*Profile, error) {
	p := defaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	p.Name = name

	/*
	 * Умолчания строк привязок кадра: правило пишут про путь и тип
	 * сообщения, и заставлять называть «префикс» и «любое направление» на
	 * каждой строке значило бы плодить одинаковые слова.
	 */
	for i := range p.Frame.Bindings {
		b := &p.Frame.Bindings[i]

		if b.Match == "" {
			b.Match = MatchPrefix
		}

		if b.Direction == "" {
			b.Direction = DirectionAny
		}
	}

	return p, nil
}

/* --- инициаторы по исходу --------------------------------------------------- */

/*
 * outcomeVerbs -- словарь канала действий со стороны ОТПРАВИТЕЛЯ: глагол и
 * оси, с которыми он бывает. Он шире того, что инспектор принимает сам
 * (threshold и skip): просить можно о чём угодно из словаря -- слушателя
 * выбирает получатель своим правилом приёма.
 *
 * Копия словаря здесь неизбежна и осознанна (docs/inspector-actions.md,
 * «Где он лежит»): за словарём по сети горячий путь не ходит. Расширение
 * начинается со схемы провода и реестра контроллера, сюда приезжает следом.
 */
var outcomeVerbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	// Переключить группу модификаторов ответа у rewrite: какую и куда,
	// называет отправитель (group + set), примет ли -- правило получателя.
	protocol.DoMutate: {protocol.ApplyRequest},
	protocol.DoReauth: {protocol.ApplySession},
	protocol.DoNote: {protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession},
	// Режим вызова соседа: исполняет модуль от любого спрошенного соседа.
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	// Глаголы записи: журнал и архив этого запроса (на кадрах -- кадра либо,
	// с conn, соединения). Исполняет модуль от любого спрошенного
	// инспектора; адресата нет -- запись маршрута.
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	// Маркер: метка события на записи. Адресат тот же -- запись маршрута, --
	// но грант ему не нужен: метка ничего не прячет.
	protocol.DoMark: {protocol.ApplyRequest},
	// Очки на маршруте: value со знаком к сумме фазы, исполняет модуль.
	protocol.DoScore: {protocol.ApplyRequest},
}

// auditVerb -- глагол записи: исполняет модуль в адрес записи маршрута,
// поля to нет; сторона set обязательна, срок, предел и набор объектов --
// только у archive с set on.
func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

/*
 * recordVerb -- адресат глагола не сосед, а запись самого маршрута: журнал,
 * архив и маркер. У всех троих поля to нет, все трое исполняются модулем и
 * потому законны на отказе -- в отличие от просьб, которым после deny некуда
 * ехать.
 */
func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

// archiveObject -- объект обменника, который умеет назвать archive.
func archiveObject(name string) bool {
	return name == "headers" || name == "args" || name == "body"
}

// controlVerb -- глагол исполняет модуль: адресат обязателен.
func controlVerb(do string) bool {
	return do == protocol.DoActive || do == protocol.DoPassive || do == protocol.DoOff ||
		do == protocol.DoVote
}

// checkPhaseAsk -- фаза вызова адресата: только у управляющих глаголов, одно
// из request, response, frame; с осью conn -- только frame либо без поля: до
// конца соединения живут одни кадры. Пусто -- всем вызовам имени.
func checkPhaseAsk(do, phase, apply string) error {
	if phase == "" {
		return nil
	}

	if !controlVerb(do) {
		return fmt.Errorf("phase is only for active, passive, vote and off")
	}

	switch phase {
	case protocol.PhaseRequest, protocol.PhaseResponse, protocol.PhaseFrame:
	default:
		return fmt.Errorf("phase must be request, response or frame, got %q", phase)
	}

	if apply == protocol.ApplyConn && phase != protocol.PhaseFrame {
		return fmt.Errorf("apply conn needs phase frame")
	}

	return nil
}

/*
 * Outcome -- строка «когда → что сделать», где «когда» это собственный
 * решённый вердикт фазы. Условие здесь -- само решение, а не его предпосылки:
 * повторённые второй строкой, они разъехались бы с политикой на первой правке.
 *
 * Действие ровно одно: просьба соседу (непустой Do) либо запись адреса клиента
 * в живой набор (непустой List). У deny просьбы не бывает -- отказ обрывает
 * фазу, и волн, которым она адресована, уже не будет.
 */
type Outcome struct {
	On string `yaml:"on"`
	// At -- порог сравнения счёта; только при On == score, и там обязателен.
	At *int `yaml:"at"`
	// Below -- сравнивать в другую сторону: score < at вместо score >= at.
	Below bool `yaml:"below"`
	// Eq -- точное сравнение: score == at. С below взаимоисключимы.
	Eq bool `yaml:"eq"`

	// Просьба соседу.
	To    string `yaml:"to"`
	Do    string `yaml:"do"`
	Apply string `yaml:"apply"`
	// Phase -- фаза вызова адресата у управляющих глаголов; пусто -- всем
	// вызовам имени.
	Phase string `yaml:"phase"`
	Delta *int   `yaml:"delta"`
	Value *int   `yaml:"value"`
	// Counter -- имя корзины получателя при do: note: селектор поверх его
	// правил приёма. Пусто -- корзину называет правило получателя.
	Counter string `yaml:"counter"`
	// Group -- только при do: mutate, обязательна: какую группу модификаторов
	// получателя переключить; куда -- тот же ключ set, что у глаголов записи.
	Group string `yaml:"group"`
	// Set -- у mutate: куда переключить группу (on | off); у глаголов записи
	// (audit, archive): писать или нет. Объекты --
	// каждый со своей стороной, размером и источником; срок -- тот же ключ
	// ttl, что у записи в набор: у строки либо просьба, либо запись.
	Set     string               `yaml:"set"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	// When -- только у archive с set on: исходы маршрута, на которых просьбу
	// исполнять (when= директивы). Пусто -- любой, включая перенаправление.
	When []string `yaml:"when"`

	// Marker -- только у mark, и там обязателен: метка события на записи.
	Marker string `yaml:"marker"`

	// Запись в живой набор: имя набора, кого писать и срок записи.
	List string `yaml:"list"`
	// Write -- субъект записи: адрес клиента, анонсированный префикс, в
	// который он попал, либо номер автономной системы целиком. Пусто -- addr.
	Write string   `yaml:"write"`
	TTL   Duration `yaml:"ttl"`

	// Code -- повод; пусто означает код решения (JSON_*).
	Code string `yaml:"code"`
}

// Asks -- эта строка просит соседа (а не пишет в набор).
func (o Outcome) Asks() bool { return o.Do != "" }

// Subject -- кого писать в набор; пустое поле означает адрес клиента.
func (o Outcome) Subject() string {
	if o.Write == "" {
		return WriteAddr
	}

	return o.Write
}

/*
 * Matches -- дёргает ли этот исход инициатор. Строки вердиктов и триггеров
 * совпадают по построению: и то и другое -- решение фазы.
 */
func (o Outcome) Matches(verdict string, score int) bool {
	switch o.On {
	case OnAllow:
		return verdict == protocol.VerdictAllow

	case OnDeny:
		return verdict == protocol.VerdictDeny

	case OnScore:
		if verdict != protocol.VerdictScore || o.At == nil {
			return false
		}

		if o.Eq {
			return score == *o.At
		}

		if o.Below {
			return score < *o.At
		}

		return score >= *o.At
	}

	return false
}

/*
 * validateOutcome -- всё, что можно поймать до трафика. Ошибка здесь стоила бы
 * не строки в логе, а отбракованного модулем ответа: действие неверной формы
 * модуль отвергает вместе со всем ответом инспектора.
 */
func validateOutcome(section string, i int, o Outcome) error {
	where := fmt.Sprintf("%s.outcomes[%d]", section, i)

	switch o.On {
	case OnDeny, OnAllow:
		if o.At != nil {
			return fmt.Errorf("%s: at is only for on: score", where)
		}

		if o.Below || o.Eq {
			return fmt.Errorf("%s: below and eq are only for on: score", where)
		}

	case OnScore:
		if o.At == nil {
			return fmt.Errorf("%s: on: score needs at", where)
		}

		if *o.At < 0 || *o.At > 100 {
			return fmt.Errorf("%s: at %d is out of 0..100", where, *o.At)
		}

		// Сравнение одно: «ровно at» и «ниже at» разом не бывают.
		if o.Below && o.Eq {
			return fmt.Errorf("%s: below and eq are mutually exclusive", where)
		}

	default:
		return fmt.Errorf("%s: unknown on %q", where, o.On)
	}

	if err := checkCode(o.Code); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	if o.Asks() && o.List != "" {
		return fmt.Errorf("%s: do and list are mutually exclusive", where)
	}

	if o.Asks() {
		return validateOutcomeAsk(where, o)
	}

	if o.List == "" {
		return fmt.Errorf("%s: neither do nor list", where)
	}

	if !nameRe.MatchString(o.List) {
		return fmt.Errorf("%s: bad dataset name %q", where, o.List)
	}

	switch o.Write {
	case "", WriteAddr, WriteNet, WriteNetAll, WriteASN:
	default:
		return fmt.Errorf("%s: write must be %s, %s, %s or %s, got %q",
			where, WriteAddr, WriteNet, WriteNetAll, WriteASN, o.Write)
	}

	// Запись без срока пережила бы причину, по которой её сделали.
	if o.TTL.Seconds() <= 0 {
		return fmt.Errorf("%s: list needs ttl", where)
	}

	return nil
}

func validateOutcomeAsk(where string, o Outcome) error {
	/*
	 * Просьба на отказе никуда не доедет: deny обрывает фазу, поздних волн не
	 * будет, и правило, собранное мышью, молча ничего бы не делало.
	 * Исключение -- глаголы записи: их исполняет модуль, а отказ -- главный
	 * случай, когда запрос стоит сохранить.
	 */
	if o.On == OnDeny && !recordVerb(o.Do) {
		return fmt.Errorf("%s: deny ends the phase, an ask has nowhere to go", where)
	}

	axes, ok := outcomeVerbs[o.Do]
	if !ok {
		return fmt.Errorf("%s: unknown verb %q", where, o.Do)
	}

	if o.Apply != "" && !hasString(axes, o.Apply) {
		return fmt.Errorf("%s: verb %q does not take apply %q", where, o.Do, o.Apply)
	}

	// Ось досочиняется там, где выбора нет: у note их четыре, и угадывать,
	// про кого сказано, нельзя -- решения по осям разные.
	// У глаголов записи умолчание -- запись запроса: профили, писанные до
	// оси response, читаются как прежде.
	if o.Apply == "" && len(axes) != 1 && !auditVerb(o.Do) {
		return fmt.Errorf("%s: %s needs apply", where, o.Do)
	}

	if o.Delta != nil && (*o.Delta < -100 || *o.Delta > 900) {
		return fmt.Errorf("%s: delta %d is out of -100..900 percent", where, *o.Delta)
	}

	if o.Value != nil && (*o.Value < -100 || *o.Value > 100) {
		return fmt.Errorf("%s: value %d is out of -100..100 percent", where, *o.Value)
	}

	/*
	 * Модуль отбракует threshold без дельты вместе со всем ответом -- не даём
	 * собрать такой профиль вовсе. Ноль запрещён по той же причине: на проводе
	 * он не отличается от отсутствия, и "ничего не менять" пишется не строкой
	 * правила, а её отсутствием.
	 */
	if o.Do == protocol.DoThreshold && (o.Delta == nil || *o.Delta == 0) {
		return fmt.Errorf("%s: threshold needs a non-zero delta", where)
	}

	if o.Do == protocol.DoNote && (o.Value == nil || *o.Value == 0) {
		return fmt.Errorf("%s: note needs a non-zero value", where)
	}

	// Очки: адресат -- сумма самого маршрута, названный сосед здесь та же
	// битая форма, что у записи; value обязателен и со знаком -- ноль на
	// проводе не отличается от отсутствия.
	if o.Do == protocol.DoScore {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module adds to the route's own sum", where, o.Do)
		}

		if o.Value == nil || *o.Value == 0 {
			return fmt.Errorf("%s: score needs a non-zero value", where)
		}
	}

	if controlVerb(o.Do) && (o.To == "" || o.To == "*") {
		return fmt.Errorf("%s: %s needs to: the module switches one call, not everyone", where, o.Do)
	}

	if err := checkPhaseAsk(o.Do, o.Phase, o.Axis()); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	// Корзина -- селектор note: у прочих глаголов ей нечего значить.
	if o.Counter != "" {
		if o.Do != protocol.DoNote {
			return fmt.Errorf("%s: counter is only for %q", where, protocol.DoNote)
		}

		if !nameRe.MatchString(o.Counter) {
			return fmt.Errorf("%s: bad counter name %q", where, o.Counter)
		}
	}

	// Группа и сторона -- только у mutate, и у mutate -- обе: "переключить"
	// без имени и стороны не просьба, а полуфраза.
	if o.Do == protocol.DoMutate {
		if o.Group == "" {
			return fmt.Errorf("%s: mutate needs a group", where)
		}

		if !nameRe.MatchString(o.Group) {
			return fmt.Errorf("%s: bad group name %q", where, o.Group)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: mutate needs set: on or off, got %q", where, o.Set)
		}
	} else if o.Group != "" {
		return fmt.Errorf("%s: group is only for %q", where, protocol.DoMutate)
	}

	/*
	 * Метка -- только у mark, и у mark она обязательна: "пометить" без метки
	 * не просьба. Адресат -- запись маршрута, поэтому названный сосед здесь
	 * та же битая форма, что у глаголов записи.
	 */
	if o.Do == protocol.DoMark {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module marks the route's own record", where, o.Do)
		}

		if err := protocol.CheckMarker(o.Marker); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
	} else if o.Marker != "" {
		return fmt.Errorf("%s: marker is only for %q", where, protocol.DoMark)
	}

	// Глагол записи: адресат -- запись маршрута, поля to нет; сторона
	// обязательна; срок, предел и набор объектов -- только у archive с set on.
	if auditVerb(o.Do) {
		if o.To != "" && o.To != "*" {
			return fmt.Errorf("%s: %s takes no to: the module writes the route's own record", where, o.Do)
		}

		if o.Set != "on" && o.Set != "off" {
			return fmt.Errorf("%s: %s needs set: on or off, got %q", where, o.Do, o.Set)
		}

		if o.Set == "off" && (o.TTL.Seconds() != 0 || len(o.When) != 0 ||
			o.Headers != nil || o.Args != nil || o.Body != nil) {
			return fmt.Errorf("%s: ttl, when and objects are only for set on", where)
		}

		if o.Do == protocol.DoAudit && (o.TTL.Seconds() != 0 || len(o.When) != 0) {
			return fmt.Errorf("%s: ttl and when are only for archive", where)
		}

		// Исход: только два слова и каждое не дважды -- как на проводе.
		if _, err := protocol.CheckArchiveWhen(o.When); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		// У записи ответа строки запроса нет.
		if o.Apply == protocol.ApplyResponse && o.Args != nil {
			return fmt.Errorf("%s: args has no meaning for the response record", where)
		}

		for _, item := range []struct {
			name string
			spec *protocol.ObjectSpec
		}{{"headers", o.Headers}, {"args", o.Args}, {"body", o.Body}} {
			if err := protocol.CheckObjectSpec(item.name, item.spec, o.Do == protocol.DoAudit); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
	}

	if !auditVerb(o.Do) && (len(o.When) != 0 ||
		o.Headers != nil || o.Args != nil || o.Body != nil) {
		return fmt.Errorf("%s: when, headers, args and body are only for audit and archive", where)
	}

	if !auditVerb(o.Do) && o.Do != protocol.DoMutate && o.Set != "" {
		return fmt.Errorf("%s: set is only for mutate, audit and archive", where)
	}

	return nil
}

// Axis -- ось просьбы с досочинённой единственной: то, что уедет на провод.
func (o Outcome) Axis() string {
	if o.Apply != "" {
		return o.Apply
	}

	if axes, ok := outcomeVerbs[o.Do]; ok && (len(axes) == 1 || auditVerb(o.Do)) {
		return axes[0]
	}

	return ""
}

func hasString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

/*
 * Повод -- тот же алфавит, что у reason.code модуля: за повод не из него
 * модуль отбраковывает ответ целиком, то есть опечатка стоила бы вердикта.
 */
func checkCode(code string) error {
	if code == "" {
		return nil
	}

	if len(code) > 64 {
		return fmt.Errorf("code is longer than 64 bytes")
	}

	if !codeRe.MatchString(code) {
		return fmt.Errorf("bad code %q", code)
	}

	return nil
}

/* --- просьбы соседей -------------------------------------------------------- */

// AnyInspector в правиле prior -- сигнал принимается от любого соседа. Для
// этого инспектора он не проходит валидацию никогда: skip ослабляет всегда, у
// threshold знак (то есть скидку) выбирает отправитель на проводе. Константа
// остаётся ради внятного текста ошибки и симметрии со словарём канала.
const AnyInspector = "*"

/*
 * Trigger -- правила приёма чужих просьб: единственное место, где действие из
 * prior что-то значит (docs/inspector-actions.md, «Сторона получателя»). Из
 * словаря инспектор применяет два глагола:
 *
 *   threshold -- коэффициент к счёту, который инспектор отдаёт модулю:
 *               проценты, множитель 1 + delta/100. Плюс -- строже, минус --
 *               скидка. Пороги не двигаются.
 *   skip      -- не проверять этот запрос вовсе.
 */
type Trigger struct {
	Prior []PriorRule `yaml:"prior"`
}

type PriorRule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	// Apply -- какие оси правило принимает; у обоих глаголов она одна -- этот
	// запрос, и ключ существует ради общей формы правил канала.
	Apply []string `yaml:"apply"`
	Codes []string `yaml:"codes"`

	// Deprecated: потолок на |delta| умер -- правило приёма решает «от кого,
	// что и по какому поводу», числа держит загрузчик отправителя
	// (-100..+900). Ключ читается и игнорируется одно поколение, чтобы
	// раскатка нового формата не спотыкалась о профили, напечатанные до неё;
	// потом станет ошибкой.
	MaxPercent int `yaml:"max_percent"`
}

// Accepts -- принимает ли правило этот глагол.
func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

// WantsAxis -- проходит ли ось через фильтр правила. Пустой список означает
// «любая допустимая при этих глаголах».
func (r PriorRule) WantsAxis(axis string) bool {
	if len(r.Apply) == 0 {
		return true
	}

	for _, a := range r.Apply {
		if a == axis {
			return true
		}
	}

	return false
}

// WantsCode -- проходит ли повод действия через фильтр правила. Пустой список
// означает «любой повод», в том числе отсутствующий.
func (r PriorRule) WantsCode(code string) bool {
	if len(r.Codes) == 0 {
		return true
	}

	for _, c := range r.Codes {
		if c == code {
			return true
		}
	}

	return false
}

/*
 * validatePrior -- ограничения загрузчика. Модель угрозы одна: один инспектор
 * скомпрометирован или сломан. Оба наших глагола умеют ослаблять -- skip
 * всегда, у threshold знак выбирает отправитель, -- поэтому послабление
 * требует имени отправителя, и широковещательного правила у этого инспектора
 * не бывает вовсе.
 */
func validatePrior(i int, r PriorRule) error {
	if r.From == "" {
		return fmt.Errorf("trigger.prior[%d]: from is empty", i)
	}

	if len(r.Accept) == 0 {
		return fmt.Errorf("trigger.prior[%d]: accept is required", i)
	}

	for _, verb := range r.Accept {
		switch verb {
		case "threshold", "skip":

		case "challenge", "reauth", "note":
			return fmt.Errorf("trigger.prior[%d]: %q is not ours to apply", i, verb)

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown verb %q", i, verb)
		}
	}

	for _, axis := range r.Apply {
		switch axis {
		case "request":

		case "ip", "asn", "session":
			return fmt.Errorf("trigger.prior[%d]: axis %q never occurs with %v",
				i, axis, r.Accept)

		default:
			return fmt.Errorf("trigger.prior[%d]: unknown axis %q", i, axis)
		}
	}

	if r.From == AnyInspector {
		return fmt.Errorf("trigger.prior[%d]: %v need a named sender: they can weaken",
			i, r.Accept)
	}

	return nil
}

/* --- проверка -------------------------------------------------------------- */

func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, observe or off, got %q", p.Mode)
	}

	// Правила приёма проверяются и у выключенного профиля: опечатка обязана
	// быть видна тогда, когда её сделали, а не когда профиль включат обратно.
	for i, r := range p.Trigger.Prior {
		if err := validatePrior(i, r); err != nil {
			return err
		}
	}

	// То же и с инициаторами: они -- вторая сторона того же канала.
	for i, o := range p.Request.Outcomes {
		if err := validateOutcome("request", i, o); err != nil {
			return err
		}
	}

	for i, o := range p.Response.Outcomes {
		if err := validateOutcome("response", i, o); err != nil {
			return err
		}
	}

	for i, o := range p.Frame.C2S.Outcomes {
		if err := validateOutcome("frame.c2s", i, o); err != nil {
			return err
		}
	}

	for i, o := range p.Frame.S2C.Outcomes {
		if err := validateOutcome("frame.s2c", i, o); err != nil {
			return err
		}
	}

	if p.Mode == ModeOff {
		// Выключенный профиль ничего не разбирает, и требовать от него
		// исправной схемы значит запретить выключение сломанного контракта.
		return nil
	}

	switch p.Schema.Kind {
	case KindOpenAPI, KindJSONSchema:
	default:
		return fmt.Errorf("schema.kind must be %s or %s, got %q",
			KindOpenAPI, KindJSONSchema, p.Schema.Kind)
	}

	if p.Schema.Source == "" && len(p.Bindings) == 0 && len(p.Frame.Bindings) == 0 {
		return fmt.Errorf("schema.source is required")
	}

	if p.Schema.Source != "" && !nameRe.MatchString(p.Schema.Source) {
		return fmt.Errorf("schema.source %q is not a valid object name", p.Schema.Source)
	}

	if p.Schema.BasePath != "" && !strings.HasPrefix(p.Schema.BasePath, "/") {
		return fmt.Errorf("schema.base_path must start with /, got %q", p.Schema.BasePath)
	}

	if !p.Request.Enabled && !p.Response.Enabled && !p.Frame.Enabled {
		return fmt.Errorf("all phases are disabled: the profile would do nothing")
	}

	if p.Request.Enabled {
		if err := validateRules("request", p.Request.Policy.Rules(), p.Request.DenyResponse); err != nil {
			return err
		}
	}

	if p.Response.Enabled {
		if err := validateRules("response", p.Response.Rules(), p.Response.DenyResponse); err != nil {
			return err
		}
	}

	if p.Frame.Enabled {
		if err := validateRules("frame.c2s", p.Frame.C2S.Policy.Rules(), p.Frame.C2S.DenyResponse); err != nil {
			return err
		}

		if err := validateRules("frame.s2c", p.Frame.S2C.Policy.Rules(), p.Frame.S2C.DenyResponse); err != nil {
			return err
		}
	}

	if err := p.validateBindings(); err != nil {
		return err
	}

	if err := p.validateFrame(); err != nil {
		return err
	}

	switch p.Audit.Values {
	case AuditValuesOff, AuditValuesHash:
	default:
		return fmt.Errorf("audit.values must be %s or %s, got %q",
			AuditValuesOff, AuditValuesHash, p.Audit.Values)
	}

	if p.Limits.MaxBody <= 0 {
		return fmt.Errorf("limits.max_body must be positive")
	}

	if p.Limits.MaxDepth < 1 {
		return fmt.Errorf("limits.max_depth must be positive")
	}

	if p.Limits.MaxErrors < 0 {
		return fmt.Errorf("limits.max_errors must not be negative")
	}

	if p.Limits.Cache < 0 {
		return fmt.Errorf("limits.cache must not be negative")
	}

	return nil
}

func (p *Profile) validateBindings() error {
	if len(p.Bindings) == 0 {
		return nil
	}

	/*
	 * Привязки и OpenAPI вместе -- два источника истины об одном: спека сама
	 * говорит, какая схема у какой операции. Расхождение между ними было бы
	 * невидимым, поэтому оно запрещено на загрузке.
	 */
	if p.Schema.Kind == KindOpenAPI {
		return fmt.Errorf("bindings are only valid with schema.kind %s: "+
			"with OpenAPI the operation picks the schema", KindJSONSchema)
	}

	for i, b := range p.Bindings {
		where := fmt.Sprintf("bindings[%d]", i)

		if b.Schema == "" {
			return fmt.Errorf("%s.schema is required", where)
		}

		if !nameRe.MatchString(b.Schema) {
			return fmt.Errorf("%s.schema %q is not a valid object name", where, b.Schema)
		}

		if b.Path == "" {
			return fmt.Errorf("%s.path is required", where)
		}

		if !strings.HasPrefix(b.Path, "/") {
			return fmt.Errorf("%s.path must start with /, got %q", where, b.Path)
		}

		switch b.Match {
		case MatchExact, MatchPrefix:
		default:
			return fmt.Errorf("%s.match must be %s or %s, got %q",
				where, MatchExact, MatchPrefix, b.Match)
		}

		for _, m := range b.Methods {
			if !methodRe.MatchString(m) {
				return fmt.Errorf("%s.methods: %q is not an upper-case method", where, m)
			}
		}
	}

	return nil
}

/*
 * validateFrame -- секция кадров. Описать сообщение сокета OpenAPI нечем,
 * поэтому включённые кадры требуют kind: jsonschema; профиль с кадрами при
 * OpenAPI не поднимается, а не пропускает их молча под видом настройки.
 */
func (p *Profile) validateFrame() error {
	if !p.Frame.Enabled {
		return nil
	}

	if p.Schema.Kind != KindJSONSchema {
		return fmt.Errorf("frame is only valid with schema.kind %s: "+
			"a socket message has no OpenAPI operation", KindJSONSchema)
	}

	if len(p.Frame.Bindings) == 0 && p.Schema.Source == "" {
		return fmt.Errorf("frame.bindings is required: without a main schema " +
			"there is nothing to check a message against")
	}

	for i, b := range p.Frame.Bindings {
		where := fmt.Sprintf("frame.bindings[%d]", i)

		if b.Schema == "" {
			return fmt.Errorf("%s.schema is required", where)
		}

		if !nameRe.MatchString(b.Schema) {
			return fmt.Errorf("%s.schema %q is not a valid object name", where, b.Schema)
		}

		if b.Path == "" {
			return fmt.Errorf("%s.path is required", where)
		}

		if !strings.HasPrefix(b.Path, "/") {
			return fmt.Errorf("%s.path must start with /, got %q", where, b.Path)
		}

		switch b.Match {
		case MatchExact, MatchPrefix:
		default:
			return fmt.Errorf("%s.match must be %s or %s, got %q",
				where, MatchExact, MatchPrefix, b.Match)
		}

		switch b.Direction {
		case DirectionC2S, DirectionS2C, DirectionAny:
		default:
			return fmt.Errorf("%s.direction must be %s, %s or %s, got %q",
				where, DirectionC2S, DirectionS2C, DirectionAny, b.Direction)
		}

		if b.Discriminator != nil {
			if !strings.HasPrefix(b.Discriminator.Pointer, "/") {
				return fmt.Errorf("%s.discriminator.pointer must be a JSON pointer starting with /, got %q",
					where, b.Discriminator.Pointer)
			}

			if b.Discriminator.Value == "" {
				return fmt.Errorf("%s.discriminator.value is required", where)
			}
		}
	}

	return nil
}

/*
 * NamedRule -- строка таблицы политик: имя исхода и что с ним делать. Порядок
 * тот же, что в панели и в документации: сначала то, что случается чаще.
 */
type NamedRule struct {
	Outcome string
	Rule    Rule
}

// Имена исходов. Одни и те же в профиле, в панели и в документации.
const (
	OutcomeInvalid          = "invalid"
	OutcomeUnparsable       = "unparsable"
	OutcomeTruncated        = "truncated"
	OutcomeUnknownOperation = "unknown_operation"
	OutcomeContentType      = "content_type"
	OutcomeUnavailable      = "unavailable"
	OutcomeStatus           = "status"
	OutcomeOpcode           = "opcode"
)

// Rules -- строки таблицы политик фазы в порядке показа.
func (r RequestRules) Rules() []NamedRule {
	return []NamedRule{
		{OutcomeInvalid, r.Invalid},
		{OutcomeUnparsable, r.Unparsable},
		{OutcomeTruncated, r.Truncated},
		{OutcomeUnknownOperation, r.UnknownOperation},
		{OutcomeContentType, r.ContentType},
		{OutcomeUnavailable, r.Unavailable},
	}
}

func (p *ResponsePhase) Rules() []NamedRule {
	return append(p.Policy.RequestRules.Rules(), NamedRule{OutcomeStatus, p.Policy.Status})
}

// Rules -- строки таблицы политик направления кадра в порядке показа.
func (r FrameRules) Rules() []NamedRule {
	return []NamedRule{
		{OutcomeInvalid, r.Invalid},
		{OutcomeUnparsable, r.Unparsable},
		{OutcomeTruncated, r.Truncated},
		{OutcomeUnknownOperation, r.UnknownOperation},
		{OutcomeOpcode, r.Opcode},
		{OutcomeUnavailable, r.Unavailable},
	}
}

// Direction -- секция направления по имени из stream.direction. Незнакомое
// направление читается как c2s: это сторона, которую модуль ведёт первой, и
// строже из двух.
func (f *FramePhase) Direction(name string) *FrameDirection {
	if name == DirectionS2C {
		return &f.S2C
	}

	return &f.C2S
}

func validateRules(phase string, rules []NamedRule, denyResponse string) error {
	denies := false

	for _, named := range rules {
		where := phase + ".policy." + named.Outcome

		if err := action(where+".action", named.Rule.Action); err != nil {
			return err
		}

		if named.Rule.Score < 0 || named.Rule.Score > 100 {
			return fmt.Errorf("%s.score must be within 0..100, got %d", where, named.Rule.Score)
		}

		if named.Rule.Action == ActionDeny {
			denies = true
		}
	}

	// Отказ без записи каталога модуль применить не сможет: код и страницу
	// отдаёт nginx по символьному имени.
	if denies && denyResponse == "" {
		return fmt.Errorf("%s.deny_response is required when a policy is %s", phase, ActionDeny)
	}

	return nil
}

func action(where, value string) error {
	switch value {
	case ActionDeny, ActionScore, ActionAllow:
		return nil
	}

	return fmt.Errorf("%s must be %s, %s or %s, got %q",
		where, ActionDeny, ActionScore, ActionAllow, value)
}

/* --- то, что спрашивают на горячем пути ------------------------------------ */

// Sources -- все документы, на которые ссылается профиль. Порядок устойчив:
// сначала основной, потом привязки в порядке объявления.
func (p *Profile) Sources() []string {
	out := make([]string, 0, len(p.Bindings)+1)
	seen := map[string]struct{}{}

	add := func(name string) {
		if name == "" {
			return
		}

		if _, ok := seen[name]; ok {
			return
		}

		seen[name] = struct{}{}
		out = append(out, name)
	}

	add(p.Schema.Source)

	for _, b := range p.Bindings {
		add(b.Schema)
	}

	for _, b := range p.Frame.Bindings {
		add(b.Schema)
	}

	return out
}

/*
 * Matches -- сошлось ли правило кадра с сообщением без учёта дискриминатора:
 * путь рукопожатия, направление и подпротокол. Дискриминатор проверяет
 * контракт, у которого на руках разобранное тело.
 */
func (b FrameBinding) Matches(path, direction, subprotocol string) bool {
	if b.Direction != DirectionAny && b.Direction != "" && b.Direction != direction {
		return false
	}

	if b.Subprotocol != "" && b.Subprotocol != subprotocol {
		return false
	}

	if b.Match == MatchExact && b.Path != path {
		return false
	}

	if b.Match == MatchPrefix && !strings.HasPrefix(path, b.Path) {
		return false
	}

	return true
}

// BindingFor -- первое совпавшее правило. Пустой список правил означает, что
// применяется основной документ.
func (p *Profile) BindingFor(method, path string) (Binding, bool) {
	for _, b := range p.Bindings {
		if b.Matches(method, path) {
			return b, true
		}
	}

	return Binding{}, false
}

// Matches -- сошлось ли правило с вызовом. Путь сравнивается настоящий, а не
// срезанный base_path: правила пишет оператор, глядя на маршрут nginx.
func (b Binding) Matches(method, path string) bool {
	if !b.matchesMethod(method) {
		return false
	}

	if b.Match == MatchExact && b.Path != path {
		return false
	}

	if b.Match == MatchPrefix && !strings.HasPrefix(path, b.Path) {
		return false
	}

	return true
}

// Пустой список методов означает «любой»: правило, написанное про путь, чаще
// всего про путь и написано.
func (b Binding) matchesMethod(method string) bool {
	if len(b.Methods) == 0 {
		return true
	}

	for _, m := range b.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}

	return false
}

// TypeAllowed -- фильтр only_types фазы ответа. Пустой список означает, что
// разбирается любое тело.
func (ph *ResponsePhase) TypeAllowed(contentType string) bool {
	if len(ph.OnlyTypes) == 0 {
		return true
	}

	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}

	for _, want := range ph.OnlyTypes {
		want = strings.ToLower(strings.TrimSpace(want))

		if strings.HasPrefix(want, "+") {
			if strings.HasSuffix(ct, want) {
				return true
			}

			continue
		}

		if ct == want {
			return true
		}
	}

	return false
}
