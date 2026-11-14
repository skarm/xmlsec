package tree //nolint:testpackage // Exercises the private DTD declaration scanner.

import (
	"errors"
	"maps"
	"testing"
)

func TestDTDScannerDeclarationsRecordNotation(t *testing.T) {
	t.Parallel()

	const subset = `<!NOTATION svg PUBLIC "  -//Example   SVG//EN " "image/svg+xml">
		<!NOTATION svg SYSTEM "ignored">
		<!NOTATION png SYSTEM "image/png">`
	const base = "urn:example:catalog"
	state := newDTDState(t.Context(), ParseOptions{Limits: DefaultLimits()})
	scanner := state.scanner(subset, base, false)
	t.Cleanup(scanner.close)
	if err := scanner.declarations(""); err != nil {
		t.Fatal(err)
	}

	want := map[string]Notation{
		"svg": {SystemID: "image/svg+xml", PublicID: "-//Example SVG//EN", BaseURI: base},
		"png": {SystemID: "image/png", BaseURI: base},
	}
	if got := state.info.Notations; !maps.Equal(got, want) {
		t.Errorf("notations = %+v, want %+v", got, want)
	}
}

func TestDTDScannerDeclarationsRejectMalformedSyntax(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, subset string }{
		{"unterminated-comment", `<!-- catalogue`},
		{"unterminated-processing-instruction", `<?catalog ready`},
		{"missing-system-literal", `<!NOTATION png SYSTEM >`},
		{"unterminated-system-literal", `<!NOTATION png SYSTEM "image/png>`},
		{"invalid-public-id-character", `<!NOTATION png PUBLIC "image[PNG]">`},
		{"qualified-notation-name", `<!NOTATION media:png SYSTEM "image/png">`},
		{"missing-attribute-separator", `<!ATTLIST catalog title CDATA "main"label CDATA #IMPLIED>`},
		{"invalid-attribute-name", `<!ATTLIST catalog a:b:label CDATA #IMPLIED>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			state := newDTDState(t.Context(), ParseOptions{Limits: DefaultLimits()})
			scanner := state.scanner(tc.subset, "", false)
			t.Cleanup(scanner.close)
			if err := scanner.declarations(""); !errors.Is(err, ErrMalformed) {
				t.Errorf("declarations(%q) = %v, want ErrMalformed", tc.subset, err)
			}
		})
	}
}

func TestDTDScannerDeclarationsBoundsCount(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, subset string
		minimum      int
	}{
		{"element-declarations", `<!ELEMENT catalog (entry*)><!ELEMENT entry EMPTY>`, 2},
		{"attribute-declarations", `<!ATTLIST catalog title CDATA #IMPLIED label CDATA #IMPLIED>`, 3},
		{"processing-instructions", `<?catalog ready?><?entries loaded?>`, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for _, test := range []struct {
				name string
				max  int
				want error
			}{
				{"at-limit", tc.minimum, nil},
				{"over-limit", tc.minimum - 1, ErrLimit},
			} {
				t.Run(test.name, func(t *testing.T) {
					limits := DefaultLimits()
					limits.MaxNodes = test.max
					state := newDTDState(t.Context(), ParseOptions{Limits: limits})
					scanner := state.scanner(tc.subset, "", false)
					t.Cleanup(scanner.close)
					if err := scanner.declarations(""); !errors.Is(err, test.want) {
						t.Errorf("declarations with MaxNodes = %d returned %v, want %v", test.max, err, test.want)
					}
				})
			}
		})
	}
}

func TestDTDScannerDeclarationsBoundsDepth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, subset string
		external     bool
	}{
		{"content-model", `<!ELEMENT catalog (entry,(title|summary)?)>`, false},
		{"ignored-section", `<![IGNORE[notes <![details]]>]]>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			for _, test := range []struct {
				name string
				max  int
				want error
			}{
				{"at-limit", 2, nil},
				{"over-limit", 1, ErrLimit},
			} {
				t.Run(test.name, func(t *testing.T) {
					limits := DefaultLimits()
					limits.MaxDepth = test.max
					state := newDTDState(t.Context(), ParseOptions{Limits: limits})
					scanner := state.scanner(tc.subset, "", tc.external)
					t.Cleanup(scanner.close)
					if err := scanner.declarations(""); !errors.Is(err, test.want) {
						t.Errorf("declarations with MaxDepth = %d returned %v, want %v", test.max, err, test.want)
					}
				})
			}
		})
	}
}
