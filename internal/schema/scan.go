package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var ErrTooDeep = errors.New("json: document is too deep")

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
			if depth == 0 {
				done = true
			}
		}
	}

	if depth != 0 {
		return fmt.Errorf("json: unexpected end of the document")
	}

	if !done && len(bytes.TrimSpace(body)) > 0 {
		return fmt.Errorf("json: no document found")
	}

	return nil
}

func Decode(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var v any

	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}

	return v, nil
}
