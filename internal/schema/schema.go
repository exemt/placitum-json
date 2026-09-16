package schema

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/pb33f/libopenapi"
	openapivalidator "github.com/pb33f/libopenapi-validator"
	valconfig "github.com/pb33f/libopenapi-validator/config"
	"github.com/pb33f/libopenapi-validator/parameters"
	"github.com/pb33f/libopenapi-validator/requests"
	"github.com/pb33f/libopenapi-validator/responses"
	"github.com/pb33f/libopenapi-validator/router"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	"github.com/pb33f/libopenapi/orderedmap"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-json/internal/audit"
	"github.com/exemt/placitum-json/internal/config"
)

const (
	OutcomeOK               = "ok"
	OutcomeMismatch         = "mismatch"
	OutcomeUnknownOperation = "unknown_operation"
	OutcomeContentType      = "content_type"
	OutcomeStatus           = "status"
)

type Input struct {
	Method  string
	Scheme  string
	Host    string
	Path    string
	Query   string
	Headers []Header
	Body    []byte

	Status int
}

type Header [2]string

type Result struct {
	Outcome   string
	Operation string
	Findings  []audit.Finding
	Errors    int
}

func (r Result) OK() bool { return r.Outcome == OutcomeOK }

type Set struct {
	byProfile map[string]*Contract
	names     []string
}

func (s *Set) Names() []string {
	if s == nil {
		return nil
	}

	return s.names
}

func (s *Set) Contract(profile string) (*Contract, bool) {
	if s == nil {
		return nil, false
	}

	c, ok := s.byProfile[profile]

	return c, ok
}

type Compiler struct {
	log *slog.Logger
}

func NewCompiler(log *slog.Logger) *Compiler { return &Compiler{log: log} }

func (c *Compiler) Compile(snap *config.Snapshot) (config.Compiled, error) {
	set := &Set{byProfile: map[string]*Contract{}}

	for _, p := range snap.All() {
		if p.Mode == config.ModeOff {
			continue
		}

		contract, err := build(p)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", p.Name, err)
		}

		set.byProfile[p.Name] = contract
		set.names = append(set.names, p.Name)

		if c.log != nil {
			c.log.Info("contract compiled",
				"profile", p.Name,
				"kind", p.Schema.Kind,
				"source", p.Schema.Source,
				"operations", contract.operations,
			)
		}
	}

	sort.Strings(set.names)

	return set, nil
}

type Contract struct {
	profile  string
	kind     string
	source   string
	basePath string

	model      *v3.Document
	router     router.Router
	params     parameters.ParameterValidator
	reqBody    requests.RequestBodyValidator
	respBody   responses.ResponseBodyValidator
	operations int

	main     *jsonschema.Schema
	byName   map[string]*jsonschema.Schema
	bindings []config.Binding
	frames   []config.FrameBinding
}

func (c *Contract) Kind() string   { return c.kind }
func (c *Contract) Source() string { return c.source }

func build(p *config.Profile) (*Contract, error) {
	c := &Contract{
		profile:  p.Name,
		kind:     p.Schema.Kind,
		source:   p.Schema.Source,
		basePath: strings.TrimSuffix(p.Schema.BasePath, "/"),
		bindings: p.Bindings,
		frames:   p.Frame.Bindings,
	}

	switch p.Schema.Kind {
	case config.KindOpenAPI:
		return c, c.buildOpenAPI(p)

	case config.KindJSONSchema:
		return c, c.buildJSONSchema(p)
	}

	return nil, fmt.Errorf("unsupported schema kind %q", p.Schema.Kind)
}

func (c *Contract) buildOpenAPI(p *config.Profile) error {
	raw, ok := p.Documents[p.Schema.Source]
	if !ok {
		return fmt.Errorf("schema %q is missing", p.Schema.Source)
	}

	doc, err := libopenapi.NewDocument(raw)
	if err != nil {
		return fmt.Errorf("openapi: %w", err)
	}

	model, err := doc.BuildV3Model()
	if err != nil {
		return fmt.Errorf("openapi: %w", err)
	}

	if model == nil {
		return fmt.Errorf("openapi: document has no v3 model")
	}

	c.model = &model.Model

	v := openapivalidator.NewValidatorFromV3Model(c.model,
		valconfig.WithoutSecurityValidation())

	c.params = v.GetParameterValidator()
	c.reqBody = v.GetRequestBodyValidator()
	c.respBody = v.GetResponseBodyValidator()

	c.router = router.NewRouter(c.model, router.WithPathOnlyMatching())

	c.operations = countOperations(c.model)

	if c.operations == 0 {
		return fmt.Errorf("openapi: document declares no operations")
	}

	return nil
}

func (c *Contract) buildJSONSchema(p *config.Profile) error {
	c.byName = map[string]*jsonschema.Schema{}

	for name, raw := range p.Documents {
		compiled, err := compileSchema(name, raw)
		if err != nil {
			return fmt.Errorf("schema %q: %w", name, err)
		}

		c.byName[name] = compiled
	}

	if p.Schema.Source != "" {
		c.main = c.byName[p.Schema.Source]
	}

	if c.main == nil && len(c.bindings) == 0 && len(c.frames) == 0 {
		return fmt.Errorf("schema %q is missing", p.Schema.Source)
	}

	return nil
}

func compileSchema(name string, raw []byte) (*jsonschema.Schema, error) {
	doc, err := decodeDocument(raw)
	if err != nil {
		return nil, err
	}

	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(offline{})

	url := "waf://schema/" + name

	if err := compiler.AddResource(url, doc); err != nil {
		return nil, err
	}

	return compiler.Compile(url)
}

type offline struct{}

func (offline) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema references are not resolved: %s", url)
}

func decodeDocument(raw []byte) (any, error) {
	var probe any

	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("document is neither JSON nor YAML: %w", err)
	}

	buf, err := json.Marshal(probe)
	if err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}

	return jsonschema.UnmarshalJSON(strings.NewReader(string(buf)))
}

func (c *Contract) request(in *Input) *http.Request {
	path := stripBase(in.Path, c.basePath)

	req := &http.Request{
		Method: in.Method,
		URL:    &url.URL{Path: path, RawQuery: in.Query},
		Header: http.Header{},
		Host:   in.Host,
		Proto:  "HTTP/1.1",
	}

	for _, h := range in.Headers {
		req.Header.Add(h[0], h[1])
	}

	if len(in.Body) > 0 {
		req.Body = bodyReader(in.Body)
		req.ContentLength = int64(len(in.Body))
	}

	return req
}

func stripBase(path, base string) string {
	if base == "" || !strings.HasPrefix(path, base) {
		return path
	}

	rest := path[len(base):]

	switch {
	case rest == "":
		return "/"

	case strings.HasPrefix(rest, "/"):
		return rest
	}

	return path
}

func countOperations(doc *v3.Document) int {
	if doc == nil || doc.Paths == nil || doc.Paths.PathItems == nil {
		return 0
	}

	n := 0

	for pair := doc.Paths.PathItems.First(); pair != nil; pair = pair.Next() {
		item := pair.Value()
		if item == nil {
			continue
		}

		n += orderedmap.Len(item.GetOperations())
	}

	return n
}

func mediaTypeFor(content *orderedmap.Map[string, *v3.MediaType], ct string) (*v3.MediaType, bool) {
	if content == nil {
		return nil, false
	}

	base := baseType(ct)

	var star, any *v3.MediaType

	for pair := content.First(); pair != nil; pair = pair.Next() {
		key := strings.ToLower(strings.TrimSpace(pair.Key()))

		switch {
		case key == base:
			return pair.Value(), true

		case strings.HasSuffix(key, "/*") && strings.HasPrefix(base, strings.TrimSuffix(key, "*")):
			star = pair.Value()

		case key == "*/*":
			any = pair.Value()
		}
	}

	if star != nil {
		return star, true
	}

	if any != nil {
		return any, true
	}

	return nil, false
}

func baseType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}

	return ct
}

func responseFor(op *v3.Operation, status int) (*v3.Response, string, bool) {
	if op == nil || op.Responses == nil {
		return nil, "", false
	}

	code := strconv.Itoa(status)

	if op.Responses.Codes != nil {
		if r, ok := op.Responses.Codes.Get(code); ok {
			return r, code, true
		}

		class := code[:1] + "XX"

		if r, ok := op.Responses.Codes.Get(class); ok {
			return r, class, true
		}

		if r, ok := op.Responses.Codes.Get(strings.ToLower(class)); ok {
			return r, class, true
		}
	}

	if op.Responses.Default != nil {
		return op.Responses.Default, "default", true
	}

	return nil, "", false
}

func headerValue(headers []Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}

	return ""
}
