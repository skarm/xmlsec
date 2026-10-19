package keyinfo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/skarm/xmlsec/keyinfo"
)

func ExampleBuild() {
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	doc, err := keyinfo.Build(ctx, keyinfo.Template{
		Names: []string{"partner signing key"},
		Keys:  []keyinfo.PublicKeyValue{{Key: key.Public(), Format: keyinfo.DERKeyValue}},
	})
	if err != nil {
		panic(err)
	}

	parsed, err := keyinfo.Parse(ctx, doc, doc.Root(), keyinfo.Options{})
	if err != nil {
		panic(err)
	}

	// Key names and candidates are untrusted hints. An application trust decision
	// is required before using a candidate to accept a signature.
	fmt.Println(parsed.KeyNames()[0], len(parsed.Candidates()))
	// Output: partner signing key 1
}
