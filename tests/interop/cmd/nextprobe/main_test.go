package main

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestOAEPOptionsAndResourceBinding(t *testing.T) {
	for _, test := range []struct {
		name string
		want crypto.Hash
	}{{"", 0}, {"1", crypto.SHA1}, {"224", crypto.SHA224}, {"256", crypto.SHA256}, {"384", crypto.SHA384}, {"512", crypto.SHA512}} {
		got, err := oaepHash(test.name)
		if err != nil || got != test.want {
			t.Fatalf("hash %q=%v %v", test.name, got, err)
		}
	}
	if _, err := oaepHash("sha256"); err == nil {
		t.Fatal("accepted a non-wire hash selector")
	}
	resource := filepath.Join(t.TempDir(), "cipher.bin")
	if err := os.WriteFile(resource, []byte{0, 1, 2, 255}, 0o600); err != nil {
		t.Fatal(err)
	}
	options, err := encryptionOptions(task{DataAlgorithm: xmlenc.AES256GCM, OAEPHash: "384", OAEPMGFHash: "256", OAEPAlgorithm: xmlenc.RSAOAEP, OAEPLabel: []byte("bound"), OAEPAllowLegacy: true, AllowLegacy: true, Resource: resource, CipherURI: "urn:exact"})
	if err != nil {
		t.Fatal(err)
	}
	if options.DataAlgorithm != xmlenc.AES256GCM || options.OAEP == nil || options.OAEP.Hash != crypto.SHA384 || options.OAEP.MGFHash != crypto.SHA256 || options.OAEP.Algorithm != xmlenc.RSAOAEP || !options.OAEP.AllowLegacy || !options.AllowLegacy || !bytes.Equal(options.OAEP.Label, []byte("bound")) || options.External == nil || options.External.URI != "urn:exact" {
		t.Fatalf("options lost fields: %+v", options)
	}
	source, err := options.External.Resolver.Resolve(t.Context(), "urn:exact")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(source)
	if err = errors.Join(err, source.Close()); err != nil || !bytes.Equal(body, []byte{0, 1, 2, 255}) {
		t.Fatalf("resource: %x %v", body, err)
	}
	if source, err := options.External.Resolver.Resolve(t.Context(), "urn:other"); source != nil || err == nil {
		t.Fatal("resolver ignored exact URI binding")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if source, err := options.External.Resolver.Resolve(ctx, "urn:exact"); source != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("resolver ignored cancellation", err)
	}
	if options, err := encryptionOptions(task{}); err != nil || options.OAEP != nil || options.External != nil {
		t.Fatalf("default options introduced features: %+v %v", options, err)
	}
	if _, err := encryptionOptions(task{OAEPMGFHash: "invalid"}); err == nil {
		t.Fatal("invalid MGF hash accepted")
	}
}

func TestElementSelectionKeepsDocumentOrder(t *testing.T) {
	doc, err := document.Parse(t.Context(), []byte(`<r xmlns:a="urn:a" xmlns:b="urn:b"><a:pick id="first"><b:pick/></a:pick><b:pick id="second"/></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	selected := selectElement(doc.Root(), "pick")
	id, _ := selected.Attribute(document.Name{Local: "id"})
	if !selected.Valid() || selected.Name().Space != "urn:a" || id != "first" {
		t.Fatalf("selection changed: %+v %q", selected.Name(), id)
	}
	if selectElement(doc.Root(), "missing").Valid() {
		t.Fatal("missing name selected a node")
	}
	if !selectElement(doc.Root(), "r").Same(doc.Root()) {
		t.Fatal("root match was skipped")
	}
}

func TestSymmetricProbeRoutesAndRejectsWrongKey(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	secret := write("key.bin", bytes.Repeat([]byte{0x51}, 32))
	plaintext := []byte("fixture bytes\x00\xff")
	input := write("input.bin", plaintext)
	for _, test := range []struct{ encrypt, decrypt string }{{nameEncryptDirect, "decrypt-direct"}, {nameEncryptWrap, "decrypt-wrap"}} {
		t.Run(test.encrypt, func(t *testing.T) {
			encrypted, err := process(t.Context(), task{Mode: test.encrypt, Input: input, Key: secret, KeyAlgorithm: xmlenc.AES256KeyWrap, DataAlgorithm: xmlenc.AES256GCM})
			if err != nil || len(encrypted.Data) == 0 || bytes.Contains(encrypted.Data, plaintext) || !bytes.Contains(encrypted.Data, []byte(xmlenc.AES256GCM)) {
				t.Fatalf("encryption route: %q %v", encrypted.Data, err)
			}
			wrapped := bytes.Contains(encrypted.Data, []byte(xmlenc.AES256KeyWrap))
			if wrapped != (test.encrypt == nameEncryptWrap) {
				t.Fatal("direct and wrapped routes were interchanged")
			}
			encoded := write(test.encrypt+".xml", encrypted.Data)
			decrypted, err := process(t.Context(), task{Mode: test.decrypt, Input: encoded, Key: secret})
			if err != nil || !bytes.Equal(decrypted.Data, plaintext) {
				t.Fatalf("decryption route: %x %v", decrypted.Data, err)
			}
			wrong := write("wrong-key.bin", bytes.Repeat([]byte{0x71}, 32))
			rejected, err := process(t.Context(), task{Mode: test.decrypt, Input: encoded, Key: wrong})
			if err == nil || len(rejected.Data) != 0 {
				t.Fatal("wrong key released plaintext")
			}
		})
	}
}
