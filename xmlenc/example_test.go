package xmlenc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func ExampleEncryptDocument() {
	ctx := context.Background()

	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	doc, err := document.Parse(ctx, []byte(`<invoice><amount>42</amount></invoice>`), document.DefaultLimits())
	if err != nil {
		panic(err)
	}

	encrypted, err := xmlenc.EncryptDocument(ctx, doc, &recipient.PublicKey, xmlenc.Options{})
	if err != nil {
		panic(err)
	}

	restored, err := xmlenc.DecryptDocument(ctx, encrypted, recipient, xmlenc.Options{})
	if err != nil {
		panic(err)
	}

	// GCM authenticates ciphertext integrity. Sender identity needs a signature.
	fmt.Println(restored.Root().Name().Local, restored.Root().Text())
	// Output: invoice 42
}

func ExampleEncryptElementWithKey() {
	ctx := context.Background()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	defer clear(key)

	doc, err := document.Parse(ctx, []byte(`<order><public>tea</public><secret>42</secret></order>`), document.DefaultLimits())
	if err != nil {
		panic(err)
	}
	// Select a handle from this snapshot; encryption returns handles in a new one.
	selected := doc.Root().Children()[1]

	encrypted, target, err := xmlenc.EncryptElementWithKey(ctx, doc, selected, key, xmlenc.SymmetricOptions{})
	if err != nil {
		panic(err)
	}

	restored, secret, err := xmlenc.DecryptElementWithKey(ctx, encrypted, target, key, xmlenc.SymmetricOptions{})
	if err != nil {
		panic(err)
	}

	// Applications own key distribution and must limit each key to 2^32 encryptions.
	fmt.Println(restored.Root().Children()[0].Text(), secret.Text())
	fmt.Println(doc.Root().Children()[1].Name().Local)
	// Output:
	// tea 42
	// secret
}
