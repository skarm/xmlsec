package reference_test

import (
	"context"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

const nameTrue = "true()"

func parse(t testing.TB, text string) *document.Document {
	t.Helper()

	d, err := document.Parse(t.Context(), []byte(text), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	return d
}

func all(t testing.TB, d *document.Document) reference.Data {
	t.Helper()

	set, err := d.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	data, err := reference.Nodes(set)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func process(t testing.TB, data reference.Data, ts []reference.Transform, opt reference.Options) *reference.Output {
	t.Helper()

	out, err := reference.Process(context.Background(), data, ts, opt)
	if err != nil {
		t.Fatal(err)
	}

	return out
}
