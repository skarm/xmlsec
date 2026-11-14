package xpath //nolint:testpackage // Exercises nilled node properties provided by the evaluator.

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestFnNilledDistinguishesSchemaPropertyFromAttribute(t *testing.T) {
	t.Parallel()
	const fixture = `<r xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><confirmed xsi:nil="true"/><unvalidated xsi:nil="true"/></r>`
	doc, err := (xdm.ParseOptions{}).ParseText(t.Context(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	expression, err := NewCompiler().Language(31, nil).Compile(`(nilled(r/confirmed), r/unvalidated ! nilled(), count(nilled(r/unvalidated/@*)), count(nilled(())))`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		mark bool
	}{
		{"validated_nilled_element", true},
		{"unvalidated_document", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evaluator := NewEvaluator(DefaultEvaluatorOptions)
			if tc.mark {
				evaluator = evaluator.NilledElements(map[xdm.Node]struct{}{doc.DocumentElement().FirstChild(): {}})
			}
			got, err := evaluator.Evaluate(t.Context(), expression, doc)
			if err != nil {
				t.Fatal(err)
			}
			assertAtomicSequence(t, got.Sequence(), []xdm.AtomicValue{
				{TypeName: xdm.TypeBoolean, Value: tc.mark},
				{TypeName: xdm.TypeBoolean, Value: false},
				{TypeName: xdm.TypeInteger, Value: int64(0)},
				{TypeName: xdm.TypeInteger, Value: int64(0)},
			})
		})
	}
}
