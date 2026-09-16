package schema

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"

	"github.com/exemt/placitum-json/internal/audit"
	"github.com/exemt/placitum-json/internal/config"
)

func bodyReader(body []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(body))
}

func (c *Contract) Request(in *Input, ch config.RequestChecks, opts Options) Result {
	opts = withDocument(opts, in.Body)

	if c.kind == config.KindJSONSchema {
		return c.requestBySchema(in, ch, opts)
	}

	req := c.request(in)

	route, err := c.router.FindRoute(req)

	switch {
	case err != nil, route == nil:
		return Result{
			Outcome: OutcomeUnknownOperation,
			Findings: []audit.Finding{note("json-unknown-path", audit.SeverityLow,
				audit.TargetURI, "", "path is not described by the specification")},
			Errors: 1,
		}

	case route.Operation == nil:
		return Result{
			Outcome:   OutcomeUnknownOperation,
			Operation: operationName(in.Method, route.Path),
			Findings: []audit.Finding{note("json-unknown-method", audit.SeverityLow,
				audit.TargetURI, route.Path,
				"the path is described, the method is not")},
			Errors: 1,
		}
	}

	res := Result{Outcome: OutcomeOK, Operation: operationName(in.Method, route.Path)}

	if ch.PathParams {
		if ok, errs := c.params.ValidatePathParamsWithPathItem(c.request(in),
			route.PathItem, route.Path); !ok {
			res.Findings = append(res.Findings,
				fromValidationErrors(errs, audit.TargetURI, opts)...)
		}
	}

	if ch.Query {
		if ok, errs := c.params.ValidateQueryParamsWithPathItem(c.request(in),
			route.PathItem, route.Path); !ok {
			res.Findings = append(res.Findings,
				fromValidationErrors(errs, audit.TargetArgs, opts)...)
		}
	}

	if ch.Headers {
		if ok, errs := c.params.ValidateHeaderParamsWithPathItem(c.request(in),
			route.PathItem, route.Path); !ok {
			res.Findings = append(res.Findings,
				fromValidationErrors(errs, audit.TargetConn, opts)...)
		}
	}

	contentType := false

	if ch.Body {
		findings, undescribed := c.requestBody(in, route.Operation, route.PathItem, route.Path, opts)
		res.Findings = append(res.Findings, findings...)
		contentType = undescribed
	}

	return finish(res, contentType, opts)
}

func (c *Contract) requestBody(in *Input, op *v3.Operation, item *v3.PathItem,
	path string, opts Options) ([]audit.Finding, bool) {

	ct := headerValue(in.Headers, "content-type")

	if len(in.Body) == 0 {
		if op.RequestBody != nil && op.RequestBody.Required != nil && *op.RequestBody.Required {
			return []audit.Finding{note("json-required-body", audit.SeverityMedium,
				audit.TargetBody, path, "the operation requires a request body")}, false
		}

		return nil, false
	}

	if op.RequestBody == nil {
		return []audit.Finding{note("json-body-not-declared", audit.SeverityLow,
			audit.TargetBody, path,
			"a body was sent, the operation declares none")}, true
	}

	if _, ok := mediaTypeFor(op.RequestBody.Content, ct); !ok {
		return []audit.Finding{note("json-content-type", audit.SeverityLow,
			audit.TargetBody, path,
			"content type "+baseType(ct)+" is not described by the operation")}, true
	}

	ok, errs := c.reqBody.ValidateRequestBodyWithPathItem(c.request(in), item, path)
	if ok {
		return nil, false
	}

	return fromValidationErrors(errs, audit.TargetBody, opts), false
}

func (c *Contract) Response(in *Input, ch config.ResponseChecks, opts Options) Result {
	opts = withDocument(opts, in.Body)

	if c.kind == config.KindJSONSchema {
		return c.responseBySchema(in, ch, opts)
	}

	req := c.request(in)

	route, err := c.router.FindRoute(req)

	switch {
	case err != nil, route == nil, route.Operation == nil:
		return Result{
			Outcome: OutcomeUnknownOperation,
			Findings: []audit.Finding{note("json-unknown-operation", audit.SeverityLow,
				audit.TargetURI, "", "the operation is not described by the specification")},
			Errors: 1,
		}
	}

	res := Result{Outcome: OutcomeOK, Operation: operationName(in.Method, route.Path)}

	declared, code, found := responseFor(route.Operation, in.Status)

	if !found {
		if !ch.Status {
			return res
		}

		res.Outcome = OutcomeStatus
		res.Errors = 1
		res.Findings = append(res.Findings, note("json-status-undeclared",
			audit.SeverityLow, audit.TargetBody, route.Path,
			"response status is not described by the operation"))

		return res
	}

	ct := headerValue(in.Headers, "content-type")

	if ch.ContentType && len(in.Body) > 0 && declared != nil && declared.Content != nil {
		if _, ok := mediaTypeFor(declared.Content, ct); !ok {
			res.Findings = append(res.Findings, note("json-content-type",
				audit.SeverityLow, audit.TargetBody, route.Path+" "+code,
				"content type "+baseType(ct)+" is not described for this status"))

			return finish(res, true, opts)
		}
	}

	if !ch.Body || len(in.Body) == 0 {
		return res
	}

	if declared == nil || declared.Content == nil {
		return res
	}

	if _, ok := mediaTypeFor(declared.Content, ct); !ok {
		return res
	}

	ok, errs := c.respBody.ValidateResponseBodyWithPathItem(c.request(in),
		c.response(in), route.PathItem, route.Path)
	if !ok {
		res.Findings = append(res.Findings, fromValidationErrors(errs, audit.TargetBody, opts)...)
	}

	return finish(res, false, opts)
}

func (c *Contract) response(in *Input) *http.Response {
	resp := &http.Response{
		StatusCode:    in.Status,
		Status:        http.StatusText(in.Status),
		Header:        http.Header{},
		Body:          bodyReader(in.Body),
		ContentLength: int64(len(in.Body)),
		Proto:         "HTTP/1.1",
	}

	for _, h := range in.Headers {
		resp.Header.Add(h[0], h[1])
	}

	if resp.Header.Get("Content-Type") == "" {
		resp.Header.Set("Content-Type", "application/json")
	}

	return resp
}

func finish(res Result, undescribed bool, opts Options) Result {
	res.Errors = len(res.Findings)

	switch {
	case res.Errors == 0:
		res.Outcome = OutcomeOK

	case undescribed && res.Errors == 1:
		res.Outcome = OutcomeContentType

	default:
		res.Outcome = OutcomeMismatch
	}

	res.Findings = trim(res.Findings, opts.MaxErrors)

	return res
}

func withDocument(opts Options, body []byte) Options {
	if !opts.HashValues || len(body) == 0 {
		return opts
	}

	if doc, err := Decode(body); err == nil {
		opts.document = doc
	}

	return opts
}

func operationName(method, path string) string {
	return strings.ToUpper(method) + " " + path
}
