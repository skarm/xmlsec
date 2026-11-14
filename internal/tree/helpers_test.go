package tree_test

import (
	"context"
	"testing"

	"github.com/skarm/xmlsec/internal/tree"
)

func treeXML(t testing.TB, doc *tree.Document) string {
	t.Helper()

	raw, err := doc.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	return string(raw)
}

type countingContext struct {
	context.Context
	remaining int
	cancel    context.CancelFunc
}

func (c *countingContext) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		c.cancel()
	}

	return c.Context.Err()
}
