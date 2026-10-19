package c14n_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

func ExampleWriteElement() {
	doc, err := document.Parse(context.Background(), []byte(`<r b="2" a="1"><empty/></r>`), document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	var out bytes.Buffer
	if err := c14n.WriteElement(context.Background(), &out, doc.Root(), c14n.Options{}); err != nil {
		// A failed write may leave partial bytes in out. Do not consume them.
		log.Fatal(err)
	}

	fmt.Println(out.String())
	// Output: <r a="1" b="2"><empty></empty></r>
}

func ExampleWriteDocument() {
	ctx := context.Background()

	doc, err := document.Parse(ctx, []byte(`<r b="2" a="1"><empty/></r>`), document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	digest := sha256.New()
	if err := c14n.WriteDocument(ctx, digest, doc, c14n.Options{MaxOutputBytes: 1 << 20}); err != nil {
		// Discard this hash state after any partial write.
		log.Fatal(err)
	}

	fmt.Printf("%x\n", digest.Sum(nil))
	// Output: 76767b27c65bb325a8268389ea596c10f59a31399c4841fc2dc459d84160d858
}
