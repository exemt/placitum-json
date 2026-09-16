package schema

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/exemt/placitum-json/internal/audit"
	"github.com/exemt/placitum-json/internal/config"
)

type FrameInput struct {
	Path        string
	Direction   string
	Subprotocol string
	Body        []byte
}

func (c *Contract) Frame(in *FrameInput, ch config.FrameChecks, opts Options) Result {
	if !ch.Body {
		return Result{Outcome: OutcomeOK}
	}

	opts = withDocument(opts, in.Body)

	if len(in.Body) == 0 {
		return Result{Outcome: OutcomeOK}
	}

	value, err := Decode(in.Body)
	if err != nil {
		return Result{
			Outcome: OutcomeMismatch,
			Findings: []audit.Finding{note("json-unparsable", audit.SeverityMedium,
				audit.TargetBody, "", err.Error())},
			Errors: 1,
		}
	}

	sch, name := c.pickFrame(in, value)

	if sch == nil {
		return Result{
			Outcome: OutcomeUnknownOperation,
			Findings: []audit.Finding{note("json-unbound", audit.SeverityLow,
				audit.TargetBody, "", "no schema is bound to this message")},
			Errors: 1,
		}
	}

	res := Result{Outcome: OutcomeOK, Operation: "frame:" + in.Direction + " " + name}

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

func (c *Contract) pickFrame(in *FrameInput, value any) (*jsonschema.Schema, string) {
	for _, b := range c.frames {
		if !b.Matches(in.Path, in.Direction, in.Subprotocol) {
			continue
		}

		if b.Discriminator != nil && !discriminates(value, b.Discriminator) {
			continue
		}

		return c.byName[b.Schema], b.Schema
	}

	if c.main != nil {
		return c.main, c.source
	}

	return nil, ""
}

func discriminates(value any, d *config.Discriminator) bool {
	found, ok := pointer(value, d.Pointer)
	if !ok {
		return false
	}

	switch v := found.(type) {
	case string:
		return v == d.Value

	case json.Number:
		return v.String() == d.Value

	case bool:
		return strconv.FormatBool(v) == d.Value

	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64) == d.Value
	}

	return false
}

func pointer(value any, ptr string) (any, bool) {
	if ptr == "" {
		return value, true
	}

	if !strings.HasPrefix(ptr, "/") {
		return nil, false
	}

	cur := value

	for _, raw := range strings.Split(ptr[1:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")

		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return nil, false
			}

			cur = next

		case []any:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}

			cur = node[i]

		default:
			return nil, false
		}
	}

	return cur, true
}
