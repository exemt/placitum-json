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
	"github.com/exemt/placitum-json/internal/decide"
	"github.com/exemt/placitum-json/internal/protocol"
	"github.com/exemt/placitum-json/internal/queue"
	"github.com/exemt/placitum-json/internal/schema"
	"github.com/exemt/placitum-json/internal/validate"
	"github.com/exemt/placitum-shared/dataset"
	"github.com/exemt/placitum-shared/netinfo"
)

const defaultDenyResponse = "json_invalid"

type handler struct {
	cfg      *config.Config
	log      *slog.Logger
	nc       *nats.Conn
	audit    *audit.Sink
	store    *config.Store
	loader   *body.Loader
	pool     *queue.Pool
	lists    *dataset.Publisher
	resolver *netinfo.Resolver
}

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

	if !h.cfg.Supports(req.V) {
		reply := protocol.ErrorReply(req, decide.CodeUnsupportedVersion)
		reply.V = protocol.Version

		h.send(msg.Reply, reply, req, audit.Details{})

		return
	}

	if req.Release != nil {
		h.log.Debug("release ignored", "rid", req.RID, "reason", req.Release.Reason)

		return
	}

	if req.Phase != protocol.PhaseRequest && req.Phase != protocol.PhaseResponse &&
		req.Phase != protocol.PhaseFrame {
		h.send(msg.Reply, protocol.ErrorReply(req, decide.CodePhaseNotSupported),
			req, audit.Details{})

		return
	}

	h.pool.Submit(&queue.Task{Req: req, Reply: msg.Reply})
}

func (h *handler) evaluate(t *queue.Task, budget time.Duration, shed string) {
	defer h.recoverInto(t.Reply, t.Req.RID)

	if shed != "" {
		h.shed(t, budget, shed)

		return
	}

	reply, det := h.inspect(t, budget)
	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) shed(t *queue.Task, budget time.Duration, shed string) {
	reply := protocol.ShedReply(t.Req, shed)
	det := audit.Details{
		Engine: map[string]any{
			"shed":      shed,
			"budget_ms": float64(budget.Microseconds()) / 1000,
		},
	}

	fired := h.overloadOnShed(t, shed, reply, det)

	h.log.Warn("shed", "rid", t.Req.RID, "reason", shed, "budget_ms", budget.Milliseconds(),
		"asks", len(fired.Actions), "lists", len(fired.Bans))

	h.send(t.Reply, reply, t.Req, det)
}

func (h *handler) inspect(t *queue.Task, budget time.Duration) (*protocol.Reply, audit.Details) {
	req := t.Req

	snap := h.store.Current()

	p, ok := h.profile(snap, req)
	if !ok {
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

	if p.Mode == config.ModeOff {
		return h.plain(req, protocol.VerdictAllow, decide.CodeProfileOff), audit.Details{}
	}

	if !phaseEnabled(p, req.Phase) {
		return h.plain(req, protocol.VerdictAllow, decide.CodePhaseDisabled), audit.Details{}
	}

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
		h.log.Error("contract is missing for a loaded profile", "rid", req.RID, "profile", p.Name)

		return protocol.ErrorReply(req, decide.CodeInternalError), audit.Details{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	started := time.Now()

	locs := []*protocol.Locator{req.Store.Headers, req.Store.Body}

	if req.Phase == protocol.PhaseRequest {
		locs = append(locs, req.Store.Args)
	}

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

	scored := d.Score

	if d.Verdict == protocol.VerdictScore {
		scored = decide.ScaleScore(d.Score, ask.Percent)
	}

	if d.WouldVerdict == protocol.VerdictScore {
		d.WouldScore = decide.ScaleScore(d.WouldScore, ask.Percent)
	}

	reply := protocol.NewReply(req, d.Verdict)

	if d.Code != "" {
		reply.Reason = &protocol.Reason{Code: d.Code}
	}

	if d.Verdict == protocol.VerdictScore {
		if err := reply.WithScore(scored); err != nil {
			h.log.Error("score out of range", "rid", req.RID, "score", d.Score)

			reply = protocol.ErrorReply(req, decide.CodeInternalError)
		}
	}

	if d.Verdict == protocol.VerdictDeny {
		reply.Response = &protocol.ResponseRef{Name: denyResponseOf(p, req)}
	}

	fired := decide.Fire(phasePolicy(p, req), effective(d, scored), req.Conn.ClientIP)

	if req.Phase == protocol.PhaseRequest {
		more := decide.FireOverload(decide.RequestPhase(p).Outcomes, t.Fill, false,
			req.Conn.ClientIP, queue.ReasonQueueLimit)
		fired.Actions = append(fired.Actions, more.Actions...)
		fired.Bans = append(fired.Bans, more.Bans...)
		fired.Names = append(fired.Names, more.Names...)
	}

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
		det.Engine["score_raw"] = d.Score
		det.Engine["score_scale_percent"] = ask.Percent
		det.Engine["score_scaled"] = scored
	}

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

	if err := h.publish(ctx, fired.Bans, req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()

		return protocol.ErrorReply(req, decide.CodeGeoUnavailable), det
	}

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

func (h *handler) profile(snap *config.Snapshot, req *protocol.Request) (*config.Profile, bool) {
	return snap.Profile(req.Route.Profile)
}

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

	if err := h.audit.Add(req, reply, det); err != nil {
		h.log.Warn("audit publish failed", "rid", reply.RID, "error", err.Error())
	}
}

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

func effective(d decide.Decision, scored int) decide.Decision {
	if d.Verdict == protocol.VerdictScore {
		d.Score = scored
	}

	return d
}

func (h *handler) publish(ctx context.Context, bans []decide.Ban, req *protocol.Request) error {
	if len(bans) == 0 || h.lists == nil {
		return nil
	}

	return writeLists(ctx, h.resolver, h.lists, h.log, req.RID, bans)
}

func (h *handler) overloadOnShed(t *queue.Task, shed string, reply *protocol.Reply,
	det audit.Details) decide.Fired {

	if shed != queue.ReasonQueueLimit || t.Req.Phase != protocol.PhaseRequest {
		return decide.Fired{}
	}

	p, ok := h.profile(h.store.Current(), t.Req)
	if !ok || p.Mode == config.ModeOff {
		return decide.Fired{}
	}

	fired := decide.FireOverload(decide.RequestPhase(p).Outcomes, t.Fill, true, t.Req.Conn.ClientIP, shed)

	if len(fired.Actions) != 0 {
		reply.Actions = fired.Actions
	}

	if len(fired.Names) != 0 {
		det.Engine["outcomes"] = fired.Names
	}

	if err := h.publish(context.Background(), fired.Bans, t.Req); err != nil {
		h.log.Error("geo unavailable for a list write", "rid", t.Req.RID,
			"profile", p.Name, "error", err.Error())

		det.Engine["geo"] = err.Error()
	}

	return fired
}
