package main

import (
	"errors"
	"testing"

	"github.com/skarm/xmlsec/transform"
)

func Example() {
	if err := run(); err != nil {
		panic(err)
	}
	// Output:
	// XPath: 2.3
	// XSLT: 2.3
}

func TestXPathTotal(t *testing.T) {
	engine, err := transform.NewEngine(transform.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		xml   string
		extra int64
		want  string
	}{
		{name: "decimal_prices_and_negative_extra", xml: `<order><price>0.10</price><price>0.25</price></order>`, extra: -1, want: "-0.65"},
		{name: "empty_order", xml: `<order/>`, extra: 3, want: "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := engine.Parse(t.Context(), []byte(tc.xml))
			if err != nil {
				t.Fatal(err)
			}
			parameters := transform.Bindings{{Local: "extra"}: transform.Values(transform.Integer(tc.extra))}
			got, err := xpathTotal(t.Context(), engine, source, parameters)
			if err != nil || got != tc.want {
				t.Errorf("XPath total=%q, error=%v, want %q and nil", got, err, tc.want)
			}
		})
	}

	t.Run("missing_parameter", func(t *testing.T) {
		source, err := engine.Parse(t.Context(), []byte(`<order/>`))
		if err != nil {
			t.Fatal(err)
		}
		got, err := xpathTotal(t.Context(), engine, source, nil)
		var evaluationError *transform.Error
		if got != "" || !errors.As(err, &evaluationError) || evaluationError.Code != "XPST0008" {
			t.Errorf("XPath total=%q, error=%v, want no result and XPST0008", got, err)
		}
	})
}
