package tree //nolint:testpackage // Exercises the private DTD content parser and lexer.

import (
	"errors"
	"slices"
	"testing"
)

func TestReadDTDStartTagPreservesRawAttributes(t *testing.T) {
	t.Parallel()

	const input = "<p:entrée\tname = 'a > b'\nlabel\t=\t\"x &amp; y\" />"
	want := []dtdRawAttribute{{name: "name", value: "a > b"}, {name: "label", value: "x &amp; y"}}
	name, attributes, empty, err := readDTDStartTag(input, 2)
	if err != nil {
		t.Fatal(err)
	}
	if name != "p:entrée" || !empty || !slices.Equal(attributes, want) {
		t.Errorf("readDTDStartTag = %q, %+v, empty %t, want p:entrée, %+v and empty element", name, attributes, empty, want)
	}
}

func TestReadDTDStartTagRejectsInvalidAttributes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input string
		maximum     int
		want        error
	}{
		{"missing-element-name", `<>`, 2, ErrMalformed},
		{"invalid-attribute-name", `<r 1title="label">`, 2, ErrMalformed},
		{"unquoted-value", `<r title=label>`, 2, ErrMalformed},
		{"unterminated-quoted-value", `<r title="label>`, 2, ErrMalformed},
		{"unterminated-tag", `<r title="label"`, 2, ErrMalformed},
		{"attribute-count", `<r title="label" page="one">`, 1, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, _, err := readDTDStartTag(tc.input, tc.maximum); !errors.Is(err, tc.want) {
				t.Errorf("readDTDStartTag(%q, %d) error = %v, want %v", tc.input, tc.maximum, err, tc.want)
			}
		})
	}
}

func TestDTDContentRejectsMalformedMarkup(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, input string }{
		{"unterminated-comment", `<r><!-- label</r>`},
		{"unterminated-processing-instruction", `<r><?catalog ready</r>`},
		{"missing-processing-instruction-target", `<r><? ready?></r>`},
		{"unterminated-start-tag", `<r><entry`},
		{"unterminated-end-tag", `<r></r`},
		{"unterminated-reference-in-attribute", `<r label="&amp"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limits := DefaultLimits()
			state := newDTDState(t.Context(), ParseOptions{Limits: limits})
			output := dtdOutput{maximum: limits.MaxBytes, maximumNodes: limits.MaxNodes}
			if err := state.content(tc.input, "", &output, true); !errors.Is(err, ErrMalformed) {
				t.Errorf("content(%q) = %v, want ErrMalformed", tc.input, err)
			}
		})
	}
}

func TestDTDContentBoundsNodes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, input string }{
		{"element", `<r><entry/></r>`},
		{"comment", `<r><!-- label --></r>`},
		{"processing-instruction", `<r><?catalog ready?></r>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			limits := DefaultLimits()
			state := newDTDState(t.Context(), ParseOptions{Limits: limits})

			atLimit := dtdOutput{maximum: limits.MaxBytes, maximumNodes: 2}
			if err := state.content(tc.input, "", &atLimit, true); err != nil || atLimit.String() != tc.input {
				t.Errorf("content with two nodes allowed = %q, %v, want %q", atLimit.String(), err, tc.input)
			}
			overLimit := dtdOutput{maximum: limits.MaxBytes, maximumNodes: 1}
			if err := state.content(tc.input, "", &overLimit, true); !errors.Is(err, ErrLimit) {
				t.Errorf("content with one node allowed = %v, want ErrLimit", err)
			}
		})
	}
}

func TestDTDContentAllowsTextAroundElementsInEntity(t *testing.T) {
	t.Parallel()

	const input = "lead<entry/>tail"
	limits := DefaultLimits()
	state := newDTDState(t.Context(), ParseOptions{Limits: limits})
	entity := dtdOutput{maximum: limits.MaxBytes, maximumNodes: limits.MaxNodes}
	if err := state.content(input, "", &entity, false); err != nil || entity.String() != input {
		t.Fatalf("entity content = (%q, %v), want (%q, nil)", entity.String(), err, input)
	}

	state = newDTDState(t.Context(), ParseOptions{Limits: limits})
	document := dtdOutput{maximum: limits.MaxBytes, maximumNodes: limits.MaxNodes}
	if err := state.content(input, "", &document, true); !errors.Is(err, ErrMalformed) {
		t.Errorf("document content error = %v, want %v", err, ErrMalformed)
	}
}
