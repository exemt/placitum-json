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

type Input struct {
	Req      *protocol.Request
	Profile  *config.Profile
	Contract *schema.Contract

	Body    body.Body
	Args    body.Body
	Headers []protocol.Header
}

type Outcome struct {
	Outcome   string
	Operation string
	Findings  []audit.Finding
	Errors    int

	Skipped string

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

func Direction(req *protocol.Request) string {
	if req.Stream == nil || req.Stream.Direction == "" {
		return config.DirectionC2S
	}

	return req.Stream.Direction
}

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

	deferred := ""

	fault := ""

	if checks.Query && in.Req.HTTP.ArgsSize > 0 &&
		(!in.Args.Available() || !in.Req.Needed(protocol.NeedArgs)) {
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

func bodyState(b body.Body, limits config.Limits) (Outcome, bool) {
	if !b.Available() {
		out := Outcome{
			Outcome:  decide.OutcomeBodyUnavailable,
			Errors:   1,
			Findings: []audit.Finding{finding("json-body-unavailable", audit.SeverityInfo, b.Unavailable)},
		}

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
