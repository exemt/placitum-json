package schema

import (
	"errors"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/exemt/placitum-json/internal/audit"
	"github.com/exemt/placitum-json/internal/config"
)

func (c *Contract) requestBySchema(in *Input, ch config.RequestChecks, opts Options) Result {
	if !ch.Body {
		return Result{Outcome: OutcomeOK}
	}

	return c.bySchema(in, opts)
}

func (c *Contract) responseBySchema(in *Input, ch config.ResponseChecks, opts Options) Result {
	if !ch.Body {
		return Result{Outcome: OutcomeOK}
	}

	return c.bySchema(in, opts)
}

func (c *Contract) bySchema(in *Input, opts Options) Result {
	sch, name := c.pick(in.Method, in.Path)

	if sch == nil {
		return Result{
			Outcome: OutcomeUnknownOperation,
			Findings: []audit.Finding{note("json-unbound", audit.SeverityLow,
				audit.TargetURI, "", "no schema is bound to this call")},
			Errors: 1,
		}
	}

	res := Result{Outcome: OutcomeOK, Operation: operationName(in.Method, name)}

	if len(in.Body) == 0 {
		return res
	}

	value, err := Decode(in.Body)
	if err != nil {
		return Result{
			Outcome: OutcomeMismatch,
			Findings: []audit.Finding{note("json-unparsable", audit.SeverityMedium,
				audit.TargetBody, name, err.Error())},
			Errors: 1,
		}
	}

	if err := sch.Validate(value); err != nil {
		var verr *jsonschema.ValidationError

		if errors.As(err, &verr) {
			res.Findings = fromSchemaError(verr, audit.TargetBody, opts)
		} else {
			res.Findings = []audit.Finding{note("json-schema", audit.SeverityMedium,
				audit.TargetBody, name, err.Error())}
		}

		res.Outcome = OutcomeMismatch
		res.Errors = len(res.Findings)
	}

	return res
}

func (c *Contract) pick(method, path string) (*jsonschema.Schema, string) {
	for _, b := range c.bindings {
		if !b.Matches(method, path) {
			continue
		}

		return c.byName[b.Schema], b.Schema
	}

	if c.main != nil {
		return c.main, c.source
	}

	return nil, ""
}
