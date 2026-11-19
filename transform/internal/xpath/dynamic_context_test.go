package xpath //nolint:testpackage // Tests private evaluator context.

import (
	"context"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestEvaluationContextOwnsItsConfiguration(t *testing.T) {
	at := time.Date(2026, 1, 1, 2, 3, 4, 0, time.UTC)
	original := EvaluationContext{CurrentTime: at, Language: "fr", Timezone: time.FixedZone("", 3600)}
	ctx := WithEvaluationContext(t.Context(), original)
	original.CurrentTime = at.Add(time.Hour)
	original.Language = "en"

	for range 2 {
		var ec evalContext
		applyBudget(ctx, &ec)

		if !ec.currentTime.Equal(at) || ec.defaultLanguage != "fr" || ec.implicitTimezone != original.Timezone {
			t.Fatal("configuration changed across nested evaluations")
		}
	}

	if got := CurrentTime(ctx, time.Time{}); !got.Equal(at) {
		t.Fatalf("invocation time: %v", got)
	}
}

type namespaceProbe struct{}

func (namespaceProbe) MinArity() int { return 0 }
func (namespaceProbe) MaxArity() int { return 0 }
func (namespaceProbe) Call(ctx context.Context, _ []xdm.Sequence) (xdm.Sequence, error) {
	uri, _ := FnNamespace(ctx, "p")
	return xdm.SingleString(uri + "|" + FnDefaultXMLNamespace(ctx)), nil
}

func TestBoundNamespaceContextAcrossEvaluationPaths(t *testing.T) {
	evaluator := NewEvaluator(DefaultEvaluatorOptions).Namespaces(map[string]string{"p": "urn:base"}).DefaultXMLNamespace("urn:xml:base").Functions(map[string]Function{"probe": namespaceProbe{}}, nil)
	state := evaluator.NewEvalState(nil)
	for _, test := range []struct {
		ns    string
		xml   string
		bound bool
	}{{"urn:first", "urn:xml:first", true}, {"urn:base", "urn:xml:base", false}, {"urn:last", "urn:xml:last", true}} {
		expression, err := NewCompiler().Compile(`probe() eq '` + test.ns + `|` + test.xml + `'`)
		if err != nil {
			t.Fatal(err)
		}
		if test.bound {
			bindings := map[string]string{"p": test.ns}
			expression = expression.BindNamespaceContext(bindings, test.xml)
			bindings["p"] = "urn:mutated"
		}
		result, err := evaluator.Evaluate(t.Context(), expression, nil)
		if err != nil {
			t.Fatal(err)
		}
		value, err := result.EBV()
		if err != nil || !value {
			t.Fatal("Evaluate", err, value, test)
		}
		value, err = evaluator.EvaluateEBV(t.Context(), expression, nil)
		if err != nil || !value {
			t.Fatal("EvaluateEBV", err, value, test)
		}
		reused, err := expression.EvaluateReuse(t.Context(), state, nil)
		if err != nil {
			t.Fatal(err)
		}
		value, err = reused.EBV()
		if err != nil || !value {
			t.Fatal("EvaluateReuse", err, value, test)
		}
	}
}

func TestEvaluateReuseUsesCurrentInvocation(t *testing.T) {
	const namespace = "urn:status"
	evaluator := NewEvaluator(DefaultEvaluatorOptions).Namespaces(map[string]string{"p": namespace}).DefaultLanguage("en")
	state := evaluator.NewEvalState(nil)
	expression, err := NewCompiler().Compile(`string-join((p:label(), string(current-dateTime()), string(default-language())), '|')`)
	if err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	for _, tc := range []struct {
		label    string
		language string
		at       time.Time
	}{
		{label: "first", language: "fr", at: at},
		{label: "second", language: "de", at: at.Add(time.Hour)},
	} {
		t.Run(tc.label, func(t *testing.T) {
			ctx := WithEvaluationContext(t.Context(), EvaluationContext{CurrentTime: tc.at, Timezone: time.UTC, Language: tc.language})
			ctx = WithFunctions(ctx, map[QualifiedName]Function{{URI: namespace, Name: "label"}: evaluatorFunction{value: tc.label}})
			want := tc.label + "|" + tc.at.Format(time.RFC3339) + "|" + tc.language
			independent, err := evaluator.Evaluate(ctx, expression, nil)
			if err != nil || independent.StringValue() != want {
				t.Fatalf("independent evaluation = %v, %v; want %q", independent, err, want)
			}
			reused, err := expression.EvaluateReuse(ctx, state, nil)
			if err != nil || reused.StringValue() != want {
				t.Fatalf("reused evaluation = %q, %v; want %q", reused.StringValue(), err, want)
			}
		})
	}

	language, err := NewCompiler().Compile(`string(default-language())`)
	if err != nil {
		t.Fatal(err)
	}

	reused, err := language.EvaluateReuse(t.Context(), state, nil)
	if err != nil || reused.StringValue() != "en" {
		t.Fatalf("base evaluation after overrides = %q, %v; want en", reused.StringValue(), err)
	}
}
