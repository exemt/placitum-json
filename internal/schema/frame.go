/*
 * Проверка сообщения сокета по отдельной JSON Schema.
 *
 * У кадра нет ни метода, ни операции, и в одном соединении вперемешку ездят
 * разные типы сообщений: {"type":"join"}, {"type":"msg"}. Схема поэтому
 * выбирается не по вызову, а по направлению и по дискриминатору -- значению
 * поля в самом теле. Правила -- frame.bindings профиля, первое совпадение
 * выигрывает; без единого совпадения сообщение контрактом не описано, и исход
 * у него тот же, что у операции, которой нет в спеке.
 *
 * Дискриминатор, а не oneOf в схеме, намеренно: с oneOf находка звучала бы
 * как «не сошлось ни с одним из пяти», а с явным типом она адресная -- «для
 * type: msg поле text обязательно».
 */

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

// FrameInput -- сообщение сокета, каким его видит проверка: адрес
// рукопожатия, кадрирование из сообщения модуля и полезная нагрузка.
type FrameInput struct {
	Path        string
	Direction   string
	Subprotocol string
	Body        []byte
}

// Frame проверяет сообщение. Исход -- не вердикт: во что его превратить,
// решает политика направления (internal/decide).
func (c *Contract) Frame(in *FrameInput, ch config.FrameChecks, opts Options) Result {
	if !ch.Body {
		return Result{Outcome: OutcomeOK}
	}

	opts = withDocument(opts, in.Body)

	if len(in.Body) == 0 {
		// Пустой кадр схемой не проверяется: «сообщение обязательно» --
		// утверждение о протоколе, а его схемой тела делать нечем.
		return Result{Outcome: OutcomeOK}
	}

	value, err := Decode(in.Body)
	if err != nil {
		// Сюда не попадают: тело разобрано до вызова. Оставлено на случай
		// расхождения разборщиков -- молча пропустить его нельзя.
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

/*
 * pickFrame выбирает схему по правилам кадра. Совпадение по пути,
 * направлению и подпротоколу -- у самого правила; дискриминатор сверяется
 * здесь, по уже разобранному телу. Ни одно правило не сошлось -- основная
 * схема профиля, если она есть: одна схема на все сообщения -- законный
 * контракт для протокола с одним типом.
 */
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

/*
 * discriminates -- «поле по указателю равно значению». Указатель -- JSON
 * pointer (RFC 6901) без экранирования за пределами ~0/~1; значение
 * сравнивается строкой: число -- своей записью, булево -- true/false. Иных
 * типов у дискриминатора не бывает: объект типом сообщения не назовёшь.
 */
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
