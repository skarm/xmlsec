package xpath //nolint:testpackage // Verify the compiler's static reference reporting.

import (
	"reflect"
	"slices"
	"testing"
)

func TestStaticReferencesVariableScopes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		source string
		want   []string
	}{
		{
			name:   "binding_initializer_runs_before_its_variable_is_bound",
			source: `for $a:x in $a:x return let $y := $b:x return ($a:x, $y, $outside, $b:x)`,
			want:   []string{"a:x", "outside"},
		},
		{
			name:   "inner_binding_restores_outer_scope_by_expanded_name",
			source: `(let $a:x := $seed return ((let $b:x := $input return $a:x), $b:x), $b:x)`,
			want:   []string{"seed", "input", "b:x"},
		},
		{
			name:   "quantified_domains_see_prior_bindings",
			source: `(every $a:x in $input, $y in $b:x satisfies ($y = $b:x), $y)`,
			want:   []string{"input", "y"},
		},
		{
			name:   "catch_binds_error_variables_only_in_its_body",
			source: `(try { $input } catch * { ($err:code, $err:description, $fallback) }, $err:code)`,
			want:   []string{"input", "fallback", "err:code"},
		},
		{
			name:   "inline_function_binds_parameter_but_captures_free_variable",
			source: `(function($a:x) { ($b:x, $closure) }($argument), $a:x)`,
			want:   []string{"closure", "argument", "a:x"},
		},
		{
			name:   "aliases_share_one_free_variable",
			source: `($b:x, $Q{urn:variables}x, $a:x, $x, $Q{}x)`,
			want:   []string{"b:x", "x"},
		},
		{
			name:   "walk_visits_predicates_and_constructor_members",
			source: `($doc/entry[$index], map { $key : [ $first, $second ] }?($lookup))`,
			want:   []string{"doc", "index", "key", "first", "second", "lookup"},
		},
	}
	ns := map[string]string{"a": "urn:variables", "b": "urn:variables", "": "urn:elements"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			expr, err := NewCompiler().Compile(tc.source)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tc.source, err)
			}
			if got := expr.StaticReferences(ns).FreeVariables; !slices.Equal(got, tc.want) {
				t.Errorf("StaticReferences(%q).FreeVariables = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

func TestStaticReferencesTypeAndFunctionNamespaces(t *testing.T) {
	t.Parallel()

	source := `(
		'raw' cast as xs:string,
		'raw' castable as Q{urn:types}Token,
		$input instance of function(array(t:Member), map(xs:string, Value*)) as document-node(element(*, Q{urn:types}Result)),
		$input treat as attribute(*, t:Code)?,
		$input/self::schema-element(e:record)/attribute::schema-attribute(e:id),
		'left' => concat('right'),
		t:format#2,
		Q{urn:functions}render(xs:string('value')),
		function($x as t:Param) as t:Output { $x }
	)`
	ns := map[string]string{"": "urn:default-type", "t": "urn:types", "e": "urn:elements"}
	want := StaticReferences{
		FreeVariables: []string{"input"},
		TypeNames: []TypeNameRef{
			{Prefix: "xs", Name: "string", URI: NSXS},
			{Name: "Token", URI: "urn:types"},
			{Prefix: "t", Name: "Member", URI: "urn:types"},
			{Prefix: "xs", Name: "string", URI: NSXS},
			{Name: "Value", URI: "urn:default-type"},
			{Name: "Result", URI: "urn:types"},
			{Prefix: "t", Name: "Code", URI: "urn:types"},
			{Prefix: "t", Name: "Param", URI: "urn:types"},
			{Prefix: "t", Name: "Output", URI: "urn:types"},
		},
		FunctionNames: []FunctionNameRef{
			{Name: "concat", URI: NSFn, Arity: 2},
			{Prefix: "t", Name: "format", URI: "urn:types", Arity: 2},
			{Name: "render", URI: "urn:functions", Arity: 1},
			{Prefix: "xs", Name: "string", URI: NSXS, Arity: 1},
		},
		SchemaComponentTests: []string{"schema-element(e:record)", "schema-attribute(e:id)"},
	}

	expr, err := NewCompiler().Compile(source)
	if err != nil {
		t.Fatalf("Compile nested types and calls: %v", err)
	}
	if got := expr.StaticReferences(ns); !reflect.DeepEqual(got, want) {
		t.Errorf("StaticReferences() = %#v, want %#v", got, want)
	}
}
