package schema

import (
	"errors"
	"strings"
	"testing"
)

/*
 * Разбор до валидации -- место, где инспектор защищается от документа, который
 * его самого и кладёт. Поэтому проверяются не только «валиден / не валиден», а
 * ровно те три случая, ради которых Scan существует: оборванный документ,
 * второй документ в том же теле и глубина.
 */
func TestScan(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		maxDepth int
		wantErr  bool
		wantDeep bool
	}{
		{name: "объект", body: `{"a":1}`, maxDepth: 8},
		{name: "массив", body: `[1,2,3]`, maxDepth: 8},
		{name: "скаляр", body: `42`, maxDepth: 8},
		{name: "пусто", body: ``, maxDepth: 8},

		// Ровно тот случай, из-за которого нельзя доверять Token(): поток
		// кончился, скобка не закрыта, ошибки нет.
		{name: "оборван", body: `{"a":1,`, maxDepth: 8, wantErr: true},
		{name: "оборван массив", body: `[1,2`, maxDepth: 8, wantErr: true},

		{name: "два документа", body: `{"a":1}{"b":2}`, maxDepth: 8, wantErr: true},
		{name: "хвост", body: `{"a":1} garbage`, maxDepth: 8, wantErr: true},

		{name: "по пределу", body: `{"a":{"b":{"c":1}}}`, maxDepth: 3},
		{name: "глубже предела", body: `{"a":{"b":{"c":1}}}`, maxDepth: 2, wantErr: true, wantDeep: true},
		{
			name:     "бомба вложенности",
			body:     strings.Repeat("[", 5000) + strings.Repeat("]", 5000),
			maxDepth: 64,
			wantErr:  true,
			wantDeep: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Scan([]byte(c.body), c.maxDepth)

			if c.wantErr && err == nil {
				t.Fatalf("Scan(%q) = nil, want an error", c.body)
			}

			if !c.wantErr && err != nil {
				t.Fatalf("Scan(%q) = %v, want nil", c.body, err)
			}

			if c.wantDeep && !errors.Is(err, ErrTooDeep) {
				t.Fatalf("Scan(%q) = %v, want ErrTooDeep", c.body, err)
			}

			if err != nil && !c.wantDeep && errors.Is(err, ErrTooDeep) {
				t.Fatalf("Scan(%q) reported depth where the document is malformed", c.body)
			}
		})
	}
}

// Числа обязаны пережить разбор без потери точности: json.Number, а не float64.
// Иначе maximum и multipleOf на больших целых врут, а врущая проверка хуже
// отсутствующей.
func TestDecodeKeepsNumbers(t *testing.T) {
	v, err := Decode([]byte(`{"id":9007199254740993}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("Decode returned %T, want an object", v)
	}

	if got := obj["id"]; got == nil || got.(interface{ String() string }).String() != "9007199254740993" {
		t.Fatalf("id = %v (%T), want json.Number 9007199254740993", got, got)
	}
}

/*
 * Хеш значения -- единственное, что позволено сделать со значением поля, когда
 * профиль просит audit.values: hash. Проверяется и то, что хеш стабилен, и то,
 * что само значение в строку не попадает: аудит живёт дольше запроса и читается
 * шире.
 */
func TestDigestHidesValue(t *testing.T) {
	doc, err := Decode([]byte(`{"customer":{"email":"person@example.com"},"items":[{"price":"free"}]}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	opts := Options{HashValues: true, document: doc}

	email := digest([]string{"customer", "email"}, opts)
	price := digest([]string{"items", "0", "price"}, opts)

	for _, got := range []string{email, price} {
		if !strings.HasPrefix(got, " value=sha256:") {
			t.Fatalf("digest = %q, want a sha256 prefix", got)
		}
	}

	if strings.Contains(email, "person@example.com") || strings.Contains(price, "free") {
		t.Fatalf("the value leaked into the audit string: %q %q", email, price)
	}

	if email == price {
		t.Fatalf("different values share a digest: %q", email)
	}

	if again := digest([]string{"customer", "email"}, opts); again != email {
		t.Fatalf("digest is not stable: %q vs %q", again, email)
	}

	// Путь, которого в документе нет, не выдумывает ни значения, ни хеша.
	if got := digest([]string{"customer", "phone"}, opts); got != "" {
		t.Fatalf("digest of a missing path = %q, want empty", got)
	}

	// Без просьбы профиля значения не трогают вовсе.
	if got := digest([]string{"customer", "email"}, Options{document: doc}); got != "" {
		t.Fatalf("digest without audit.values = %q, want empty", got)
	}
}
