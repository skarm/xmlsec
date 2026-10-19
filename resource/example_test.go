package resource_test

import (
	"context"
	"fmt"
	"io"
	"testing/fstest"

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
