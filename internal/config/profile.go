package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/exemt/placitum-json/internal/overload"
	"github.com/exemt/placitum-json/internal/protocol"
)

const (
	ModeEnforce = "enforce"
	ModeObserve = "observe"
	ModeOff     = "off"

	KindOpenAPI    = "openapi"
	KindJSONSchema = "jsonschema"

	ActionDeny  = "deny"
	ActionScore = "score"
	ActionAllow = "allow"

	MatchExact  = "exact"
	MatchPrefix = "prefix"

	OnDeny  = ActionDeny
	OnAllow = ActionAllow
	OnScore = ActionScore

	WriteAddr   = "addr"
	WriteNet    = "net"
	WriteNetAll = "net_all"
	WriteASN    = "asn"

	AuditValuesOff  = "off"
	AuditValuesHash = "hash"
)

const DefaultName = "default"

const ProbeName = "_probe"

const SchemaFilePrefix = "schema-"

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	methodRe = regexp.MustCompile(`^[A-Z]+$`)
	codeRe   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

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

type Profile struct {
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

	Documents map[string][]byte `yaml:"-"`
}

type Schema struct {
	Kind   string `yaml:"kind"`
	Source string `yaml:"source"`

	BasePath string `yaml:"base_path"`
}

type Rule struct {
	Action string `yaml:"action"`
	Score  int    `yaml:"score"`
}

type RequestRules struct {
	Invalid          Rule `yaml:"invalid"`
	Unparsable       Rule `yaml:"unparsable"`
	Truncated        Rule `yaml:"truncated"`
	UnknownOperation Rule `yaml:"unknown_operation"`
	ContentType      Rule `yaml:"content_type"`
	Unavailable      Rule `yaml:"unavailable"`
}

type ResponseRules struct {
	RequestRules `yaml:",inline"`
	Status       Rule `yaml:"status"`
}

type RequestChecks struct {
	Body       bool `yaml:"body"`
	Query      bool `yaml:"query"`
	PathParams bool `yaml:"path_params"`
	Headers    bool `yaml:"headers"`
}

type ResponseChecks struct {
	Body        bool `yaml:"body"`
	Status      bool `yaml:"status"`
	ContentType bool `yaml:"content_type"`
}

type RequestPhase struct {
	Enabled      bool          `yaml:"enabled"`
	Checks       RequestChecks `yaml:"checks"`
	Policy       RequestRules  `yaml:"policy"`
	DenyResponse string        `yaml:"deny_response"`
	Outcomes     []Outcome     `yaml:"outcomes"`
}

type ResponsePhase struct {
	Enabled      bool           `yaml:"enabled"`
	Checks       ResponseChecks `yaml:"checks"`
	Policy       ResponseRules  `yaml:"policy"`
	OnlyTypes    []string       `yaml:"only_types"`
	DenyResponse string         `yaml:"deny_response"`
	Outcomes     []Outcome      `yaml:"outcomes"`
}

type Binding struct {
	Methods []string `yaml:"methods"`
	Path    string   `yaml:"path"`
	Match   string   `yaml:"match"`
	Schema  string   `yaml:"schema"`
}

type FramePhase struct {
	Enabled  bool           `yaml:"enabled"`
	Bindings []FrameBinding `yaml:"bindings"`
	C2S      FrameDirection `yaml:"c2s"`
	S2C      FrameDirection `yaml:"s2c"`
}

type FrameBinding struct {
	Path          string         `yaml:"path"`
	Match         string         `yaml:"match"`
	Direction     string         `yaml:"direction"`
	Subprotocol   string         `yaml:"subprotocol"`
	Discriminator *Discriminator `yaml:"discriminator"`
	Schema        string         `yaml:"schema"`
}

type Discriminator struct {
	Pointer string `yaml:"pointer"`
	Value   string `yaml:"value"`
}

type FrameChecks struct {
	Body bool `yaml:"body"`
}

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

const (
	DirectionC2S = "c2s"
	DirectionS2C = "s2c"
	DirectionAny = "any"
)

const (
	OpcodeText         = "text"
	OpcodeBinary       = "binary"
	OpcodeContinuation = "continuation"
)

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

func defaults(name string) *Profile {
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

func ParseProfile(name string, raw []byte) (*Profile, error) {
	p := defaults(name)

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}

	p.Name = name

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

var outcomeVerbs = map[string][]string{
	protocol.DoChallenge: {protocol.ApplyRequest},
	protocol.DoThreshold: {protocol.ApplyRequest},
	protocol.DoSkip:      {protocol.ApplyRequest},
	protocol.DoMutate:    {protocol.ApplyRequest},
	protocol.DoReauth:    {protocol.ApplySession},
	protocol.DoNote: {protocol.ApplyRequest, protocol.ApplyIP,
		protocol.ApplyASN, protocol.ApplySession},
	protocol.DoActive:  {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoPassive: {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoOff:     {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoVote:    {protocol.ApplyRequest, protocol.ApplyConn},
	protocol.DoAudit:   {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoArchive: {protocol.ApplyRequest, protocol.ApplyResponse},
	protocol.DoMark:    {protocol.ApplyRequest},
	protocol.DoScore:   {protocol.ApplyRequest},
}

func auditVerb(do string) bool {
	return do == protocol.DoAudit || do == protocol.DoArchive
}

func recordVerb(do string) bool {
	return auditVerb(do) || do == protocol.DoMark || do == protocol.DoScore
}

func controlVerb(do string) bool {
	return do == protocol.DoActive || do == protocol.DoPassive || do == protocol.DoOff ||
		do == protocol.DoVote
}

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

type Outcome struct {
	On    string `yaml:"on"`
	At    *int   `yaml:"at"`
	Below bool   `yaml:"below"`
	Eq    bool   `yaml:"eq"`

	To      string               `yaml:"to"`
	Do      string               `yaml:"do"`
	Apply   string               `yaml:"apply"`
	Phase   string               `yaml:"phase"`
	Delta   *int                 `yaml:"delta"`
	Value   *int                 `yaml:"value"`
	Counter string               `yaml:"counter"`
	Group   string               `yaml:"group"`
	Set     string               `yaml:"set"`
	Headers *protocol.ObjectSpec `yaml:"headers"`
	Args    *protocol.ObjectSpec `yaml:"args"`
	Body    *protocol.ObjectSpec `yaml:"body"`
	When    []string             `yaml:"when"`

	Marker string `yaml:"marker"`

	List  string   `yaml:"list"`
	Write string   `yaml:"write"`
	TTL   Duration `yaml:"ttl"`

	Code string `yaml:"code"`
}

func (o Outcome) Asks() bool { return o.Do != "" }

func (o Outcome) Subject() string {
	if o.Write == "" {
		return WriteAddr
	}

	return o.Write
}

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

		if o.Below && o.Eq {
			return fmt.Errorf("%s: below and eq are mutually exclusive", where)
		}

	case OnOverload:
		if section != "request" {
			return fmt.Errorf("%s: on: %s is only for the request section", where, OnOverload)
		}

		if err := overload.Check(o.At); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		if o.Below || o.Eq {
			return fmt.Errorf("%s: below and eq are only for on: score", where)
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

	if o.TTL.Seconds() <= 0 {
		return fmt.Errorf("%s: list needs ttl", where)
	}

	return nil
}

func validateOutcomeAsk(where string, o Outcome) error {
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

	if o.Apply == "" && len(axes) != 1 && !auditVerb(o.Do) {
		return fmt.Errorf("%s: %s needs apply", where, o.Do)
	}

	if o.Delta != nil && (*o.Delta < -100 || *o.Delta > 900) {
		return fmt.Errorf("%s: delta %d is out of -100..900 percent", where, *o.Delta)
	}

	if o.Value != nil && (*o.Value < -100 || *o.Value > 100) {
		return fmt.Errorf("%s: value %d is out of -100..100 percent", where, *o.Value)
	}

	if o.Do == protocol.DoThreshold && (o.Delta == nil || *o.Delta == 0) {
		return fmt.Errorf("%s: threshold needs a non-zero delta", where)
	}

	if o.Do == protocol.DoNote && (o.Value == nil || *o.Value == 0) {
		return fmt.Errorf("%s: note needs a non-zero value", where)
	}

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

	if o.Counter != "" {
		if o.Do != protocol.DoNote {
			return fmt.Errorf("%s: counter is only for %q", where, protocol.DoNote)
		}

		if !nameRe.MatchString(o.Counter) {
			return fmt.Errorf("%s: bad counter name %q", where, o.Counter)
		}
	}

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

		if _, err := protocol.CheckArchiveWhen(o.When); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

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

func checkCode(code string) error {
	if code == "" {
		return nil
	}

	if !codeRe.MatchString(code) {
		return fmt.Errorf("code %q is not [A-Z][A-Z0-9_]{0,63}", code)
	}

	return nil
}

const AnyInspector = "*"

type Trigger struct {
	Prior []PriorRule `yaml:"prior"`
}

type PriorRule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	Apply  []string `yaml:"apply"`
	Codes  []string `yaml:"codes"`
}

func (r PriorRule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

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

func (p *Profile) Validate() error {
	switch p.Mode {
	case ModeEnforce, ModeObserve, ModeOff:
	default:
		return fmt.Errorf("mode must be enforce, observe or off, got %q", p.Mode)
	}

	for i, r := range p.Trigger.Prior {
		if err := validatePrior(i, r); err != nil {
			return err
		}
	}

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

type NamedRule struct {
	Outcome string
	Rule    Rule
}

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

func (p *Profile) BindingFor(method, path string) (Binding, bool) {
	for _, b := range p.Bindings {
		if b.Matches(method, path) {
			return b, true
		}
	}

	return Binding{}, false
}

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

const OnOverload = overload.On
