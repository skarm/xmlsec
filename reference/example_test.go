package reference_test

import (
	"context"
	"fmt"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
)

func ExampleProcess() {
	ctx := context.Background()

	doc, err := document.Parse(ctx, []byte(`<order><item ID="item-1" b="2" a="1">tea</item></order>`), document.DefaultLimits())
	if err != nil {
		panic(err)
	}

	resolver, err := reference.NewSameDocumentResolver(ctx, doc, document.Name{Local: "ID"})
	if err != nil {
		panic(err)
	}

	selected, err := resolver.Resolve(ctx, "#item-1")
	if err != nil {
		panic(err)
	}

	output, err := reference.Process(ctx, selected.Data(), []reference.Transform{{Algorithm: c14n.Exclusive}}, reference.Options{})
	if err != nil {
		panic(err)
	}

	// These are digest input bytes, not proof that a signature is valid.
	fmt.Println(string(output.Bytes()))
	// Output: <item ID="item-1" a="1" b="2">tea</item>
}
