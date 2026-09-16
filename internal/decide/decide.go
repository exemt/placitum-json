package decide

import (
	"github.com/exemt/placitum-json/internal/config"
	"github.com/exemt/placitum-json/internal/overload"
	"github.com/exemt/placitum-json/internal/protocol"
	"github.com/exemt/placitum-json/internal/schema"
)

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
	CodeFrameOpcode      = "JSON_FRAME_OPCODE"

	CodeObserve = "JSON_OBSERVE"

	CodeUnknownProfile     = "JSON_UNKNOWN_PROFILE"
	CodeSkipped            = "JSON_SKIPPED"
	CodePhaseNotSupported  = "JSON_PHASE_NOT_SUPPORTED"
	CodePhaseDisabled      = "JSON_PHASE_DISABLED"
	CodeProfileOff         = "JSON_PROFILE_OFF"
	CodeInternalError      = "JSON_INTERNAL_ERROR"
	CodeStoreUnavailable   = "JSON_STORE_UNAVAILABLE"
	CodeGeoUnavailable     = "JSON_GEO_UNAVAILABLE"
	CodeMalformedRequest   = "JSON_MALFORMED_REQUEST"
	CodeUnsupportedVersion = "JSON_UNSUPPORTED_VERSION"
)

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

type Decision struct {
	Verdict      string
	Score        int
	Code         string
	DenyResponse string

	WouldVerdict string
	WouldScore   int
	WouldCode    string
}

type Phase struct {
	Mode         string
	Rules        map[string]config.Rule
	DenyResponse string
	Outcomes     []config.Outcome
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

type Ban struct {
	Dataset string
	Write   string
	Addr    string
	TTL     int
	Reason  string
}

type Fired struct {
	Actions []protocol.Action
	Bans    []Ban
	Names   []string
}

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

	if o.Do == protocol.DoArchive && o.Set == "on" && o.TTL.Seconds() > 0 {
		ttl := int64(o.TTL.Seconds())
		out.TTL = &ttl
	}

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

func reason(o config.Outcome, code string) string {
	if o.Code != "" {
		return o.Code
	}

	return code
}

func outcomeName(o config.Outcome) string {
	if o.Asks() {
		return o.Do
	}

	return o.List
}

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
