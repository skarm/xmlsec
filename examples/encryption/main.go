// Command encryption demonstrates selected XML encryption and explicit key profiles.
// Demonstrates explicit selection and immutable XMLENC snapshots. The ephemeral
// recipient key is local demo data; production trust/key management is external.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	source, err := document.Parse(ctx, []byte(`<Envelope xmlns="urn:example" xmlns:p="urn:private"><Header>visible</Header><p:Payload>private</p:Payload></Envelope>`), document.DefaultLimits())
	if err != nil {
		return err
	}

	selected := source.Root().Children()[1]
	oaepOptions := xmlenc.Options{OAEP: &xmlenc.OAEPParameters{Hash: crypto.SHA384, Label: []byte("example-profile")}}

	encrypted, encryptedElement, err := xmlenc.EncryptElement(ctx, source, selected, &recipient.PublicKey, oaepOptions)
	if err != nil {
		return err
	}
	// After transport, parse the received XML and select the expected element
	// again according to the application's protocol. Old handles cannot be reused.
	restored, payload, err := xmlenc.DecryptElement(ctx, encrypted, encryptedElement, recipient, oaepOptions)
	if err != nil {
		return err
	}
	// Decryption alone does not authenticate the sender. The application must
	// validate signatures and protocol semantics before acting on the payload.
	fmt.Printf("Restored %s in %s; original payload is %s; header is %s\n",
		payload.Name().Local, restored.Root().Name().Local, selected.Text(), restored.Root().Children()[0].Text())
	// Content mode keeps Payload and its attributes visible while protecting all
	// its child nodes. Decryption returns the restored parent, even for empty text.
	contentCipher, encryptedContent, err := xmlenc.EncryptContent(ctx, source, selected, &recipient.PublicKey, xmlenc.Options{})
	if err != nil {
		return err
	}

	contentPlain, parent, err := xmlenc.DecryptContent(ctx, contentCipher, encryptedContent, recipient, xmlenc.Options{})
	if err != nil {
		return err
	}

	fmt.Printf("Restored content of %s: %s; header is %s\n",
		parent.Name().Local, parent.Text(), contentPlain.Root().Children()[0].Text())
	// The application can also distribute a direct AES data key independently.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	defer clear(secret)

	direct, err := xmlenc.EncryptBytesWithKey(ctx, []byte("opaque bytes"), secret, xmlenc.SymmetricOptions{})
	if err != nil {
		return err
	}

	const uri = "urn:example:stored-ciphertext"

	external, _, body, err := xmlenc.ExternalizeCiphertext(ctx, direct, direct.Root(), uri)
	if err != nil {
		return err
	}
	// This in-memory resolver represents an exact application-approved resource.
	// Production transports must also honor cancellation during blocked reads.
	options := xmlenc.SymmetricOptions{Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{
		URI: uri, MaxBytes: len(body), Resolver: xmlenc.CipherResolverFunc(func(ctx context.Context, gotURI string) (io.ReadCloser, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			if gotURI != uri {
				return nil, errors.New("unexpected ciphertext URI")
			}

			return io.NopCloser(bytes.NewReader(body)), nil
		}),
	}}}

	plain, err := xmlenc.DecryptBytesWithKey(ctx, external, secret, options)
	if err != nil {
		return err
	}
	defer clear(plain)

	if string(plain) != "opaque bytes" {
		return errors.New("unexpected decrypted content")
	}

	fmt.Println("Authenticated direct-key ciphertext from the exact external resource")

	return nil
}
