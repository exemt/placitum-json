package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	valerrors "github.com/pb33f/libopenapi-validator/errors"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/exemt/placitum-json/internal/audit"
)

type Options struct {
	MaxErrors  int
	Paths      bool
	HashValues bool

	document any
}

const evidenceMax = 256

var printer = message.NewPrinter(language.English)

func fromValidationErrors(errs []*valerrors.ValidationError, target string,
	opts Options) []audit.Finding {

	out := make([]audit.Finding, 0, len(errs))

	for _, err := range errs {
		if err == nil {
			continue
		}

		if len(err.SchemaValidationErrors) == 0 {
			out = append(out, audit.Finding{
				Code:     codeFor(err.ValidationType, err.ValidationSubType),
				Severity: audit.SeverityMedium,
				Target:   targetFor(err, target),
				Rule:     err.SpecPath,
				Evidence: evidence(reasonOf(err), "", opts),
			})

			continue
		}

		for _, sve := range err.SchemaValidationErrors {
			if sve == nil {
				continue
			}

			path, keyword := locate(sve)

			out = append(out, audit.Finding{
				Code:     "json-" + keyword,
				Severity: audit.SeverityMedium,
				Target:   targetFor(err, target),
				Rule:     rule(sve),
				Evidence: evidence(sve.Reason, path, opts) + digest(instanceOf(sve), opts),
			})
		}
	}

	return trim(out, opts.MaxErrors)
}

func fromSchemaError(err *jsonschema.ValidationError, target string,
	opts Options) []audit.Finding {

	if err == nil {
		return nil
	}

	var out []audit.Finding

	var walk func(e *jsonschema.ValidationError)

	walk = func(e *jsonschema.ValidationError) {
		if e == nil {
			return
		}

		if len(e.Causes) == 0 {
			path := "/" + strings.Join(e.InstanceLocation, "/")
			if len(e.InstanceLocation) == 0 {
				path = "/"
			}

			out = append(out, audit.Finding{
				Code:     "json-" + keywordOf(e),
				Severity: audit.SeverityMedium,
				Target:   target,
				Rule:     e.SchemaURL,
				Evidence: evidence(e.ErrorKind.LocalizedString(printer), path, opts) +
					digest(e.InstanceLocation, opts),
			})

			return
		}

		for _, cause := range e.Causes {
			walk(cause)
		}
	}

	walk(err)

	return trim(out, opts.MaxErrors)
}

func note(code, severity, target, rule, text string) audit.Finding {
	return audit.Finding{
		Code:     code,
		Severity: severity,
		Target:   target,
		Rule:     rule,
		Evidence: clamp(text),
	}
}

func locate(sve *valerrors.SchemaValidationFailure) (path, keyword string) {
	if orig := sve.OriginalJsonSchemaError; orig != nil {
		path = "/" + strings.Join(orig.InstanceLocation, "/")
		if len(orig.InstanceLocation) == 0 {
			path = "/"
		}

		return path, keywordOf(orig)
	}

	if kw := lastSegment(sve.KeywordLocation); kw != "" {
		return "", kw
	}

	return "", "schema"
}

func keywordOf(e *jsonschema.ValidationError) string {
	if e == nil || e.ErrorKind == nil {
		return "schema"
	}

	kp := e.ErrorKind.KeywordPath()
	if len(kp) == 0 {
		return "schema"
	}

	return kp[len(kp)-1]
}

func rule(sve *valerrors.SchemaValidationFailure) string {
	if sve.KeywordLocation != "" {
		return sve.KeywordLocation
	}

	return sve.ReferenceSchema
}

func evidence(reason, path string, opts Options) string {
	reason = strings.TrimSpace(reason)

	if path != "" && opts.Paths {
		return clamp(path + ": " + reason)
	}

	return clamp(reason)
}

func clamp(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= evidenceMax {
		return s
	}

	return s[:evidenceMax-1] + "…"
}

func digest(loc []string, opts Options) string {
	if !opts.HashValues || opts.document == nil {
		return ""
	}

	value, ok := valueAt(opts.document, loc)
	if !ok {
		return ""
	}

	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}

	return " value=" + Hash(raw)
}

func Hash(value []byte) string {
	sum := sha256.Sum256(value)

	return "sha256:" + hex.EncodeToString(sum[:8])
}

func instanceOf(sve *valerrors.SchemaValidationFailure) []string {
	if sve == nil || sve.OriginalJsonSchemaError == nil {
		return nil
	}

	return sve.OriginalJsonSchemaError.InstanceLocation
}

func valueAt(doc any, loc []string) (any, bool) {
	cur := doc

	for _, step := range loc {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[step]
			if !ok {
				return nil, false
			}

			cur = next

		case []any:
			i, err := strconv.Atoi(step)
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

func reasonOf(err *valerrors.ValidationError) string {
	if err.Reason != "" {
		return err.Reason
	}

	return err.Message
}

func targetFor(err *valerrors.ValidationError, def string) string {
	switch strings.ToLower(err.ValidationSubType) {
	case "query":
		return audit.TargetArgs

	case "path":
		return audit.TargetURI

	case "header":
		if name := strings.ToLower(err.ParameterName); name != "" {
			return "header:" + name
		}

		return audit.TargetConn

	case "cookie":
		if name := strings.ToLower(err.ParameterName); name != "" {
			return "cookie:" + name
		}

		return audit.TargetConn
	}

	return def
}

func codeFor(kind, sub string) string {
	parts := []string{"json"}

	for _, p := range []string{kind, sub} {
		if p = slug(p); p != "" {
			parts = append(parts, p)
		}
	}

	if len(parts) == 1 {
		return "json-invalid"
	}

	return strings.Join(parts, "-")
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))

	var b strings.Builder

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)

		case r == ' ' || r == '_' || r == '-' || r == '.':
			b.WriteByte('-')
		}
	}

	return strings.Trim(b.String(), "-")
}

func lastSegment(path string) string {
	if path == "" {
		return ""
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")

	return parts[len(parts)-1]
}

func trim(in []audit.Finding, max int) []audit.Finding {
	if max <= 0 || len(in) <= max {
		return in
	}

	out := in[:max:max]

	return append(out, audit.Finding{
		Code:     "json-errors-truncated",
		Severity: audit.SeverityInfo,
		Target:   audit.TargetBody,
		Evidence: fmt.Sprintf("%d more findings are not listed", len(in)-max),
	})
}
