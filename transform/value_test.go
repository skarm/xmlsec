package transform_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skarm/xmlsec/transform"
)

func TestTypedValues(t *testing.T) {
	if value, err := transform.Values(transform.Integer(1), transform.Integer(2)).EffectiveBoolean(); err == nil {
		t.Fatal(value)
	}

	m, err := transform.Map(transform.MapEntry{Key: transform.String("a"), Value: transform.Values(transform.Integer(1))})
	if err != nil {
		t.Fatal(err)
	}

	entry, ok := m.Lookup(transform.String("a"))
	if !ok || text(t, entry) != "1" {
		t.Fatal(entry, ok)
	}

	a := transform.Array(entry)

	member, err := a.Member(0)
	if err != nil || text(t, member) != "1" {
		t.Fatal(member, err)
	}

	if _, err = a.Member(1); err == nil {
		t.Fatal("index accepted")
	}

	date := transform.DateTime(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	if date.Type().Local != "dateTime" {
		t.Fatal(date.Type())
	}

	if _, err = transform.Map(transform.MapEntry{Key: transform.String("a")}, transform.MapEntry{Key: transform.String("a")}); err == nil {
		t.Fatal("duplicate key")
	}
}

func TestFunctionValuesConcurrentReuse(t *testing.T) {
	e := engine(t, transform.Config{})
	for _, source := range []string{`function($n){sum(1 to $n)}`, `sum#1`, `function-lookup(QName("http://www.w3.org/2005/xpath-functions","sum"),1)`} {
		callable := evaluate(t, e, source, transform.XPath31)

		q := query(t, e, `$f(1 to 10)`, transform.XPath31)
		if strings.HasPrefix(source, "function(") {
			q = query(t, e, `$f(10)`, transform.XPath31)
		}

		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				out, err := q.Evaluate(context.Background(), nil, transform.XPathContext{Variables: transform.Bindings{{Local: "f"}: callable}})
				if err != nil {
					t.Error(err)
					return
				}

				got, err := out.Text()
				if err != nil || got != "55" {
					t.Error(got, err)
				}
			})
		}

		wg.Wait()
	}
}
