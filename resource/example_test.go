package resource_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing/fstest"

	"github.com/skarm/xmlsec/evidence"

	"github.com/skarm/xmlsec/resource"
)

func ExampleNewFSResolver() {
	files := fstest.MapFS{"invoice.xml": &fstest.MapFile{Data: []byte(`<invoice/>`)}}

	resolver, err := resource.NewFSResolver(resource.FSConfig{FS: files, BaseURI: "embed:/documents/"})
	if err != nil {
		panic(err)
	}

	stream, err := resolver.Resolve(context.Background(), "embed:/documents/invoice.xml")
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))
	// Output: <invoice/>
}

func Example_evidenceStore() {
	store, err := evidence.NewStore("", 1<<20)
	if err != nil {
		panic(err)
	}
	defer store.Close()
	// Store the exact untrusted bytes; authenticate them separately on replay.
	record, err := store.PutReader(context.Background(), evidence.CRL, strings.NewReader("untrusted CRL bytes"), evidence.Provenance{}, 1<<20)
	if err != nil {
		panic(err)
	}
	defer record.Close()
	reader, err := record.Open(context.Background())
	if err != nil {
		panic(err)
	}
	defer reader.Close()
	n, err := io.Copy(io.Discard, reader)
	if err != nil {
		panic(err)
	}

	fmt.Println(record.Kind(), n)
	// Output: crl 19
}
