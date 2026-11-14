package xmlenc_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestECDHDocumentRestoresRootAndPreservesSnapshot(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	key, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := parse(t, []byte(`<r xmlns="urn:root" xmlns:p="urn:payload"><p:value>déjà vu</p:value></r>`))
	before := xmlBytes(t, source)
	options := xmlenc.ECDHOptions{KeyAlgorithm: xmlenc.AES192KeyWrap, RecipientKeyName: "document recipient"}
	encrypted, err := xmlenc.EncryptDocumentWithECDH(ctx, source, key.PublicKey(), options)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := encrypted.Root().Name(), (document.Name{Space: xmlenc.Namespace, Local: "EncryptedData"}); got != want {
		t.Fatalf("encrypted root = %v, want %v", got, want)
	}
	restored, err := xmlenc.DecryptDocumentWithECDH(ctx, encrypted, key, options, xmlenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sameXML(t, source, restored)
	if restored.Root().Same(source.Root()) || !bytes.Equal(xmlBytes(t, source), before) {
		t.Fatal("round trip lost snapshot isolation")
	}
}

func TestECDHElementAndContentRetainSelection(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source := parse(t, []byte(`<r xmlns:p="urn:payload"><p:box flag="public">one<p:item>two</p:item>three</p:box><tail/></r>`))
	selection := source.Root().Children()[0]
	before := xmlBytes(t, source)
	options := xmlenc.ECDHOptions{Data: xmlenc.CipherOptions{DataAlgorithm: xmlenc.AES128GCM}}

	for _, tc := range []struct {
		name    string
		encrypt func(*document.Document, document.Element) (*document.Document, document.Element, error)
		decrypt func(*document.Document, document.Element) (*document.Document, document.Element, error)
		cipher  func(*document.Document) document.Element
	}{
		{
			name: "element",
			encrypt: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
				return xmlenc.EncryptElementWithECDH(ctx, d, e, key.PublicKey(), options)
			},
			decrypt: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
				return xmlenc.DecryptElementWithECDH(ctx, d, e, key, options, xmlenc.DecryptOptions{})
			},
			cipher: func(d *document.Document) document.Element { return d.Root().Children()[0] },
		},
		{
			name: "content",
			encrypt: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
				return xmlenc.EncryptContentWithECDH(ctx, d, e, key.PublicKey(), options)
			},
			decrypt: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
				return xmlenc.DecryptContentWithECDH(ctx, d, e, key, options, xmlenc.DecryptOptions{})
			},
			cipher: func(d *document.Document) document.Element { return d.Root().Children()[0].Children()[0] },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encrypted, cipher, err := tc.encrypt(source, selection)
			if err != nil {
				t.Fatal(err)
			}
			if !cipher.Same(tc.cipher(encrypted)) || cipher.Name().Local != "EncryptedData" {
				t.Fatalf("encrypted selection = %v, want the new EncryptedData element at the selected position", cipher.Name())
			}
			restored, selected, err := tc.decrypt(encrypted, cipher)
			if err != nil {
				t.Fatal(err)
			}
			if !selected.Same(restored.Root().Children()[0]) || selected.Same(selection) {
				t.Fatal("restored selection did not identify the box in the new snapshot")
			}
			sameXML(t, source, restored)
			if !bytes.Equal(xmlBytes(t, source), before) {
				t.Fatal("original document changed during encryption or decryption")
			}
			if got, selected, err := tc.decrypt(encrypted, selection); got != nil || selected.Valid() || !errors.Is(err, xmlenc.ErrFormat) {
				t.Errorf("decryption with a foreign handle returned (%v, %v, %v), want ErrFormat and no result", got, selected, err)
			}
		})
	}
}
