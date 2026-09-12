/*
 * Разбор тела до валидации.
 *
 * Два вопроса решаются здесь, и оба до того, как схема вообще увидит документ:
 * это вообще JSON -- и не пытается ли он положить процесс глубиной. Обход
 * дерева схемы рекурсивен, и десять тысяч вложенных массивов кладут не схему, а
 * стек; поэтому глубина считается на разборе потоком, без сборки значения.
 */

package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrTooDeep -- документ глубже предела профиля. Отдельная ошибка, потому что
// исход у неё свой: это не «не сошлось со схемой», а «мы не стали смотреть».
var ErrTooDeep = errors.New("json: document is too deep")

/*
 * Scan проверяет, что тело -- корректный JSON, и что его глубина не больше
 * maxDepth. Значение не собирается: Token() идёт потоком, и на теле в мегабайт
 * это дешевле разбора в any примерно вдвое.
 */
func Scan(body []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	depth := 0
	done := false

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("json: %w", err)
		}

		/*
		 * Второй документ в том же теле -- не «валидный JSON с хвостом», а два
		 * документа там, где схема ждёт один. Пропускать такое как валидное
		 * нельзя: приложение прочитает первый, проверка -- тоже первый, а
		 * второй достанется тому, кто читает иначе.
		 */
		if done {
			return fmt.Errorf("json: trailing data after the document")
		}

		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{', '[':
				depth++

				if maxDepth > 0 && depth > maxDepth {
					return ErrTooDeep
				}

			case '}', ']':
				depth--

				if depth == 0 {
					done = true
				}
			}

		default:
			// Скаляр верхнего уровня -- сам по себе законченный документ.
			if depth == 0 {
				done = true
			}
		}
	}

	/*
	 * Незакрытые скобки на конце потока. Token() их не ловит: он отдаёт EOF,
	 * не проверяя, закрылось ли начатое, -- и оборванный документ выглядел бы
	 * разобранным. Для JSON это ровно тот случай, ради которого существует
	 * политика on_unparsable.
	 */
	if depth != 0 {
		return fmt.Errorf("json: unexpected end of the document")
	}

	if !done && len(bytes.TrimSpace(body)) > 0 {
		return fmt.Errorf("json: no document found")
	}

	return nil
}

// Decode собирает значение для валидатора JSON Schema. UseNumber обязателен:
// без него 64-битные целые уезжают в float64, и проверка multipleOf или
// maximum на больших числах врёт.
func Decode(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var v any

	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}

	return v, nil
}
