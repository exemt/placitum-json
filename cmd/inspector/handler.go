/*
 * Конвейер одного сообщения: разбор -> очередь -> бюджет -> профиль -> обменник ->
 * проверка -> политика -> ответ.
 *
 * Каждый шаг делегирован своему пакету; здесь только порядок и то, что ответ
 * уходит на каждом пути, включая панику внутри обработки. Молчание неотличимо
 * от перегрузки, см. docs/inspectors.md#контракт.
 *
 * Ответ несёт решение и код причины. Список нарушений схемы уезжает отдельным
 * событием kind=inspector, уже после ответа: подробностями дедлайн волны
 * двигать нельзя.
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-json/internal/audit"
	"github.com/exemt/placitum-json/internal/body"
	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/dataset"
	"github.com/exemt/placitum-json/internal/decide"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-json/internal/protocol"
	"github.com/exemt/placitum-json/internal/queue"
	"github.com/exemt/placitum-json/internal/schema"
	"github.com/exemt/placitum-json/internal/validate"
)

/*
 * Запись каталога отказов на случай, когда своей взять неоткуда: профиль не
 * найден, а именно он называет запись. Имя заводится миграцией контроллера в
 * каждом пространстве.
 */
const defaultDenyResponse = "json_invalid"

type handler struct {
	cfg    *config.Config
	log    *slog.Logger
	nc     *nats.Conn
	audit  *audit.Sink
	store  *config.Store
	loader *body.Loader
	pool   *queue.Pool
	// lists -- публикатор активных наборов: им пишут инициаторы по исходу
	// («на отказе -- субъект в набор»).
	lists *dataset.Publisher
	// resolver -- кодер гео: анонсы и состав системы, когда инициатор пишет
	// не адрес (net, net_all, asn). nil -- кодера нет: такие строки отвечают
	// error, адрес пишется как всегда.
	resolver *netinfo.Resolver
}

/*
 * receive исполняется в потоке приёма и обязан быть дешёвым: разбор нужен,
 * потому что без deadline_ms не проверить бюджет, а всё остальное уходит в пул
 * воркеров.
 */
func (h *handler) receive(msg *nats.Msg) {
	defer h.recoverInto(msg.Reply, "")

	req, err := protocol.Parse(msg.Data)
	if err != nil {
		rid := ""

		var pe *protocol.ParseError
		if errors.As(err, &pe) {
			rid = pe.RID
		}

		h.log.Warn("message rejected", "error", err.Error(), "bytes", len(msg.Data))
		h.send(msg.Reply, protocol.FallbackReply(rid, h.cfg.Name, decide.CodeMalformedRequest),
			nil, audit.Details{})

		return
	}

	/*
	 * Незнакомая версия схемы -- error: разъезд модуля и инспектора означает,
	 * что проверки не было, и решать это должен маршрут. Прежний deny блокировал
	 * трафик за ошибку развёртывания, прежний allow пропускал бы его под видом
	 * проверенного -- обе половины были догадкой.
	 */
	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, decide.CodeUnsupportedVersion)
		reply.V = protocol.Version

		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	/*
	 * Освобождение состояния к json не относится: фазы у него не связаны, и
	 * держать между ними нечего. Ответа на такое сообщение нет -- слот в
	 * модуле уже закрыт, -- поэтому просто выходим.
	 */
	if req.Release != nil {
		h.log.Debug("release ignored", "rid", req.RID, "reason", req.Release.Reason)

		return
	}

	/* Сообщение не своей фазы -- то же расхождение конфигурации. */
	if req.Phase != protocol.PhaseRequest && req.Phase != protocol.PhaseResponse &&
		req.Phase != protocol.PhaseFrame {
		h.send(msg.Reply, protocol.ErrorReply(req, decide.CodePhaseNotSupported),
			req, audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

// evaluate исполняется воркером. shed непустой означает, что проверка не
// начиналась: очередь была полна либо бюджет уже вышел.
func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		h.shed(t, budget, shed)

		return
	}

	reply, det := h.inspect(t, budget)
	h.send(t.Reply, reply, t.Req, det)
}

/*
 * shed -- ответ на сообщение, которое мы не смотрели.
 *
 * Полная очередь -- всегда allow: инспектор, который под нагрузкой начинает
 * отказывать всем, ломает контур надёжнее любой атаки, а решение по причине
 * принимает модуль. Истёкший бюджет -- исход профиля (on_budget): там, где
 * контракт гейтит по-настоящему, «не успели» может значить «не пропускаем».
 */
func (h *handler) shed(t *queue.Task, budget time.Duration, shed string) {
	/*
	 * Контракт не проверен -- ни по очереди, ни по бюджету, -- и выбирать за
	 * маршрут между пропуском и отказом инспектор больше не пытается. Раньше
	 * исход budget стоял в профиле: он говорил то же, что теперь говорит
	 * waf_exception класса inspector, но словами инспектора и мимо маршрута.
	 */
	reply := protocol.ShedReply(t.Req, shed)

	h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds())

	h.send(t.Reply, reply, t.Req, audit.Details{
		Engine: map[string]any{
			"shed":      shed,
			"budget_ms": float64(budget.Microseconds()) / 1000,
		},
	})
}

func (h *handler) inspect(t *queue.Task, budget time.Duration) (*protocol.Reply, audit.Details) {
	req := t.Req

	/*
	 * Снимок берётся один раз на сообщение. Два обращения к Current() дали бы
	 * профиль из одного поколения и контракт из другого, если между ними
	 * приедет новое: расхождение редкое, воспроизводится раз в месяц и
	 * выглядит как отказ исправному запросу.
	 */
	snap := h.store.Current()

	p, ok := h.profile(snap, req)
	if !ok {
		/*
		 * Профиля нет, и откатиться на default не разрешено политикой запуска:
		 * применять нечего. Это ошибка конфигурации контура, и распорядиться ею
		 * -- дело маршрута.
		 */
		reply := protocol.ErrorReply(req, decide.CodeUnknownProfile)

		h.log.Warn("unknown profile", "rid", req.RID,
			"profile", req.Route.Profile)

		return reply, audit.Details{
			Findings: []audit.Finding{{
				Code:     "json-unknown-profile",
				Severity: audit.SeverityCritical,
				Target:   audit.TargetURI,
				Rule:     req.Route.Profile,
			}},
		}
	}

	// Выключенный профиль -- это выключатель, а не отсутствие проверки: ответ
	// с причиной, по которой в аудите видно, что маршрут не проверяется.
	if p.Mode == config.ModeOff {
		return h.plain(req, protocol.VerdictAllow, decide.CodeProfileOff), audit.Details{}
	}

	if !phaseEnabled(p, req.Phase) {
		return h.plain(req, protocol.VerdictAllow, decide.CodePhaseDisabled), audit.Details{}
	}

	/*
	 * Просьбы соседей -- против правил приёма профиля: skip снимает проверку
	 * до контракта и обменника, threshold -- коэффициент к счёту, который уедет
	 * модулю. Исход каждой просьбы обязан попасть в kind=inspector.
	 */
	ask := decide.EvaluatePrior(req.Prior, p.Trigger.Prior)

	if ask.Skip {
		reply := protocol.NewReply(req, protocol.VerdictAllow)
		reply.Reason = &protocol.Reason{Code: decide.CodeSkipped}

		h.log.Info("skipped by a prior ask",
			"rid", req.RID,
			"uri", req.HTTP.URI,
			"profile", p.Name,
		)

		return reply, audit.Details{Engine: map[string]any{
			"profile": p.Name,
			"skip":    true,
			"actions": ask.Outcomes,
		}}
	}

	set, _ := snap.Compiled().(*schema.Set)

	contract, ok := set.Contract(p.Name)
	if !ok {
		/*
		 * Профиль есть, контракта нет: снимок собран не до конца. Разойтись эти
		 * два множества могут только из-за ошибки в загрузчике -- проверять
		 * нечем, и это наш сбой, а не свойство запроса. Прежний deny отвечал за
		 * маршрут; теперь исход выбирает waf_exception класса inspector.
		 */
		h.log.Error("contract is missing for a loaded profile", "rid", req.RID, "profile", p.Name)

		return protocol.ErrorReply(req, decide.CodeInternalError), audit.Details{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	started := time.Now()

	/*
	 * Объекты обменника одним походом: заголовки и тело всегда, строка запроса --
	 * только на фазе запроса. Порознь это были до трёх последовательных
	 * round-trip внутри бюджета волны, на каждом запросе.
	 */
	locs := []*protocol.Locator{req.Store.Headers, req.Store.Body}

	if req.Phase == protocol.PhaseRequest {
		locs = append(locs, req.Store.Args)
	}

	// У кадра заголовков нет: контекст рукопожатия -- в request_store, а схема
	// выбирается по кадрированию и телу, не по нему.
	if req.Phase == protocol.PhaseFrame {
		locs[0] = nil
	}

	got := h.loader.LoadMany(ctx, locs...)

	in := validate.Input{
		Req:      req,
		Profile:  p,
		Contract: contract,
		Headers:  h.headers(req, got[0]),
		Body:     got[1],
	}

	if req.Phase == protocol.PhaseRequest {
		in.Args = got[2]
	}

	out := validate.Run(in)

	/*
	 * Объект лежал, а обменник его не отдал: контракт не проверен. Политике
	 * профиля такой исход не подчиняется -- строка unavailable описывает тело,
	 * которого не дал маршрут, а здесь не дали нам, и о запросе это не говорит
	 * ничего.
	 */
	if out.Fault != "" {
		h.log.Warn("store fetch failed", "rid", req.RID, "profile", p.Name,
			"reason", out.Fault)

		return protocol.ErrorReply(req, decide.CodeStoreUnavailable), audit.Details{
			EngineMS: float64(time.Since(started).Microseconds()) / 1000,
			Findings: out.Findings,
			Engine:   map[string]any{"profile": p.Name, "store": out.Fault},
		}
	}

	d := decide.From(phasePolicy(p, req), out.Outcome)

	/*
	 * Коэффициент просьб threshold применяется к отдаваемому счёту: пороги --
	 * и правил профиля, и маршрута -- не двигаются, меняется цена поведения
	 * клиента на этом запросе.
	 */
	scored := d.Score

	if d.Verdict == protocol.VerdictScore {
		scored = decide.ScaleScore(d.Score, ask.Percent)
	}

	// В наблюдении коэффициент ложится на решение enforce: по нему судят
	// инициаторы, и оператор видит то же число, которое увидел бы в бою.
	if d.WouldVerdict == protocol.VerdictScore {
		d.WouldScore = decide.ScaleScore(d.WouldScore, ask.Percent)
	}

	reply := protocol.NewReply(req, d.Verdict)

	if d.Code != "" {
		reply.Reason = &protocol.Reason{Code: d.Code}
	}

	if d.Verdict == protocol.VerdictScore {
		if err := reply.WithScore(scored); err != nil {
			// Счёт вне диапазона отбраковал бы ответ целиком, то есть
			// инспектор молча выпал бы из решения. Лучше allow с записью.
			h.log.Error("score out of range", "rid", req.RID, "score", d.Score)

			reply = protocol.ErrorReply(req, decide.CodeInternalError)
		}
	}

	if d.Verdict == protocol.VerdictDeny {
		reply.Response = &protocol.ResponseRef{Name: denyResponseOf(p, req)}
	}

	/*
	 * Инициаторы по исходу: просьбы уезжают этим же ответом, записи в наборы --
	 * после него. Сравнивают они тот счёт, который уходит модулю, поэтому
	 * решение отдаётся сюда уже с коэффициентом соседа.
	 */
	fired := decide.Fire(phasePolicy(p, req), effective(d, scored), req.Conn.ClientIP)

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	det := audit.Details{
		EngineMS: float64(time.Since(started).Microseconds()) / 1000,
		Findings: out.Findings,
		Engine: map[string]any{
			"profile":   p.Name,
			"mode":      p.Mode,
			"phase":     req.Phase,
			"kind":      contract.Kind(),
			"schema":    contract.Source(),
			"outcome":   out.Outcome,
			"errors":    out.Errors,
			"truncated": in.Body.Truncated,
			"body_size": len(in.Body.Data),
		},
	}

	if out.Operation != "" {
		det.Engine["operation"] = out.Operation
	}

	// Кадрирование: без него находка на кадре неотличима от находки на
	// запросе с тем же адресом, а conn склеивает кадры с рукопожатием.
	if req.Phase == protocol.PhaseFrame {
		det.Engine["conn"] = req.ConnID
		det.Engine["seq"] = req.Seq
		det.Engine["direction"] = validate.Direction(req)
		det.Engine["opcode"] = validate.Opcode(req)
	}

	if out.Skipped != "" {
		det.Engine["skipped"] = out.Skipped
	}

	if len(ask.Outcomes) != 0 {
		det.Engine["actions"] = ask.Outcomes
	}

	if ask.Percent != 0 && d.Verdict == protocol.VerdictScore {
		// Тройка чисел коэффициента: без неё вердикт не объяснить.
		det.Engine["score_raw"] = d.Score
		det.Engine["score_scale_percent"] = ask.Percent
		det.Engine["score_scaled"] = scored
	}

	// Наблюдение: passive стоит на каждой записи профиля -- ответ модулю
	// заглушён, -- а would_* только там, где было что глушить.
	if p.Mode == config.ModeObserve {
		det.Engine["passive"] = true
	}

	if d.WouldVerdict != "" {
		det.Engine["would_verdict"] = d.WouldVerdict
		det.Engine["would_code"] = d.WouldCode

		if d.WouldVerdict == protocol.VerdictScore {
			det.Engine["would_score"] = d.WouldScore
		}
	}

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	/*
	 * Строка требует кодер, а кодер молчит: запись в набор не состоялась.
	 * Молча пропустить нельзя -- бан, которого не было, выглядит как бан, --
	 * поэтому error, и что делать с запросом, решает waf_exception; решение
	 * контракта остаётся в записи аудита.
	 */
	if err := h.publish(ctx, fired.Bans, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, decide.CodeGeoUnavailable), det
	}

	// Наблюдение наружу не делает ничего, но обязано показать, что сделало бы.
	h.log.Info("verdict",
		"rid", req.RID,
		"inspector", req.Inspector,
		"phase", req.Phase,
		"wave", req.Wave,
		"method", req.HTTP.Method,
		"uri", req.HTTP.URI,
		"profile", p.Name,
		"operation", out.Operation,
		"outcome", out.Outcome,
		"verdict", reply.Verdict,
		"passive", p.Mode == config.ModeObserve,
		"would_verdict", d.WouldVerdict,
		"would_code", d.WouldCode,
		"reason", d.Code,
		"errors", out.Errors,
		"asks", len(fired.Actions),
		"lists", len(fired.Bans),
		"engine_ms", det.EngineMS,
		"budget_ms", budget.Milliseconds(),
	)

	return reply, det
}

/*
 * profile выбирает профиль по тегу маршрута. Имени нет среди загруженных --
 * применять нечего: чужой контракт это не более мягкая проверка, а проверка не
 * того, и отката на default здесь больше нет. Вызывающий отвечает error.
 */
func (h *handler) profile(snap *config.Snapshot, req *protocol.Request) (*config.Profile, bool) {
	return snap.Profile(req.Route.Profile)
}

/*
 * loadHeaders -- заголовки из обменника. Объект лежит там JSON-массивом пар:
 * порядок получения значим, а дубликаты имён в объекте потерялись бы.
 *
 * На фазе ответа это заголовки **ответа**: контекст запроса приезжает
 * секцией request_store и для выбора операции не нужен -- метод и путь едут
 * инлайном.
 */
func (h *handler) headers(req *protocol.Request, loaded body.Body) []protocol.Header {
	if !loaded.Available() || len(loaded.Data) == 0 {
		return nil
	}

	var pairs []protocol.Header

	if err := json.Unmarshal(loaded.Data, &pairs); err != nil {
		h.log.Warn("headers blob is not an array of pairs", "rid", req.RID, "error", err.Error())

		return nil
	}

	return pairs
}

func (h *handler) plain(req *protocol.Request, verdict, code string) *protocol.Reply {
	reply := protocol.NewReply(req, verdict)
	reply.Reason = &protocol.Reason{Code: code}

	return reply
}

func phaseEnabled(p *config.Profile, phase string) bool {
	switch phase {
	case protocol.PhaseResponse:
		return p.Response.Enabled

	case protocol.PhaseFrame:
		return p.Frame.Enabled
	}

	return p.Request.Enabled
}

/*
 * Политики фазы. У кадра они свои у каждого направления, и направление
 * приезжает в сообщении: обработчик один на все три фазы, а разницу между
 * ними держит профиль.
 */
func phasePolicy(p *config.Profile, req *protocol.Request) decide.Phase {
	switch req.Phase {
	case protocol.PhaseResponse:
		return decide.ResponsePhase(p)

	case protocol.PhaseFrame:
		return decide.FramePhase(p, validate.Direction(req))
	}

	return decide.RequestPhase(p)
}

func denyResponseOf(p *config.Profile, req *protocol.Request) string {
	name := p.Request.DenyResponse

	switch req.Phase {
	case protocol.PhaseResponse:
		name = p.Response.DenyResponse

	case protocol.PhaseFrame:
		name = p.Frame.Direction(validate.Direction(req)).DenyResponse
	}

	if name == "" {
		return defaultDenyResponse
	}

	return name
}

func (h *handler) send(subject string, reply *protocol.Reply, req *protocol.Request,
	det audit.Details) {

	if subject == "" {
		h.log.Error("no reply subject in message", "rid", reply.RID)

		return
	}

	payload, err := reply.Marshal()
	if err != nil {
		// Ответ, который нельзя сериализовать, всё равно должен уйти: иначе
		// волна ждёт до дедлайна впустую.
		h.log.Error("reply marshal failed", "rid", reply.RID, "error", err.Error())

		payload, err = protocol.FallbackReply(reply.RID, reply.Inspector,
			decide.CodeInternalError).Marshal()
		if err != nil {
			return
		}
	}

	if err := h.nc.Publish(subject, payload); err != nil {
		h.log.Error("respond failed", "rid", reply.RID, "error", err.Error())
	}

	/*
	 * Аудит после inbox: волна уже получила ответ. Обычный PUB на subject из
	 * сообщения, без JS API. Ошибка сюда не возвращается.
	 */
	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

/*
 * Паника внутри обработки одного сообщения обязана быть перехвачена и
 * превращена в allow с машинным кодом причины, а не в падение процесса: баг
 * разбора не должен становиться отказом в обслуживании.
 */
func (h *handler) recoverInto(subject, rid string) {
	r := recover()
	if r == nil {
		return
	}

	h.log.Error("handler panicked", "rid", rid, "panic", r, "stack", string(debug.Stack()))

	if subject == "" {
		return
	}

	h.send(subject, protocol.FallbackReply(rid, h.cfg.Name, decide.CodeInternalError),
		nil, audit.Details{})
}

/*
 * effective -- решение с тем счётом, который уходит модулю: инициаторы обязаны
 * сравнивать порог с ним, иначе оператор смотрел бы на одно число, а сосед
 * своим коэффициентом двигал другое. В наблюдении наружу не ушло ничего, и
 * масштабируется would-счёт -- показать надо то, что случилось бы.
 */
func effective(d decide.Decision, scored int) decide.Decision {
	if d.Verdict == protocol.VerdictScore {
		d.Score = scored
	}

	return d
}

/*
 * publish -- записи инициаторов в активные наборы, см. lists.go: адрес как
 * есть, анонсы и состав системы -- у кодера, в бюджете сообщения; кодер
 * спрашивается только строкой, которой он нужен. Отказ keeper не отменяет
 * ничего: этот запрос уже решён. Ошибка -- кодер нужен и молчит.
 */
func (h *handler) publish(ctx context.Context, bans []decide.Ban, req *protocol.Request) error {
	if len(bans) == 0 || h.lists == nil {
		return nil
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, bans)
}
