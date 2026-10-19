package document_test

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/skarm/xmlsec/document"
)

func ExampleParse() {
	doc, err := document.Parse(context.Background(), []byte(`<message xmlns="urn:example:messages">hello</message>`), document.DefaultLimits())
	if err != nil {
		log.Fatal(err)
	}

	root := doc.Root()
	fmt.Println(root.Name().Space, root.Name().Local)
	fmt.Println(root.Text())
	// Output:
	// urn:example:messages message
	// hello
}

func ExampleReadRecords() {
	input := strings.NewReader(`<feed><item>a</item><item>b</item></feed>`)
	options := document.RecordOptions{
		Path:          []document.Name{{Local: "feed"}, {Local: "item"}},
		MaxInputBytes: 1 << 20,
		MaxRecords:    100,
	}

	err := document.ReadRecords(context.Background(), input, options, func(record *document.Document) error {
		fmt.Println(record.Root().Text())
		return nil
	})
	if err != nil {
		// Earlier callback effects are not rolled back by a later XML error.
		log.Fatal(err)
	}

	// Output:
	// a
	// b
}
