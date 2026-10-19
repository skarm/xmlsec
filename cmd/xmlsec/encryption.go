package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"flag"
	"io"
	"path/filepath"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func runEncryption(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("encryption "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "-", "input XML or plaintext bytes")
	output := fs.String("out", "-", "output XML or authenticated plaintext")
	keyFile := fs.String("key", "", "RSA public/private key or raw AES key file")
	transport := fs.String("transport", nameRSA, "key transport: rsa, wrap or direct")
	scope := fs.String("scope", scopeBytes, "plaintext scope: bytes, document, element or content")
	algorithm := fs.String("algorithm", xmlenc.AES256GCM, "data encryption algorithm URI")
	wrap := fs.String("wrap-algorithm", xmlenc.AES256KeyWrap, "AES key wrap algorithm URI")
	name := fs.String("key-name", "", "exact untrusted KeyName hint for direct-key mode")
	oaepHash := fs.String("oaep-hash", "sha256", "RSA-OAEP digest and MGF1 hash")
	labelFile := fs.String("oaep-label-file", "", "optional exact OAEP label bytes")
	maximum := fs.Int("max-plaintext-bytes", 8<<20, "maximum plaintext bytes (up to 32 MiB)")
	id := fs.String("id", "", "exact selected element ID (element/content encryption or EncryptedData selection)")
	idAttr := fs.String("id-attr", "ID", "selection ID attribute local name")
	idNS := fs.String("id-ns", "", "selection ID namespace")
	index := fs.Int("index", -1, "explicit zero-based EncryptedData index for decrypt/externalize")
	resources := fs.String("resources", "", "trusted URI/path-only manifest containing one external ciphertext")
	uri := fs.String("uri", "", "absolute URI for externalize")
	cipherOut := fs.String("cipher-out", "", "raw ciphertext output path for externalize (required)")
	keyFlags := registerPrivateKeyFlags(fs)

	specific := "in out id id-attr id-ns index uri cipher-out"
	if cmd != "externalize" {
		specific = "in out key transport scope algorithm wrap-algorithm key-name oaep-hash oaep-label-file max-plaintext-bytes id id-attr id-ns"
		if cmd == nameDecrypt {
			specific += " index resources" + privateKeyFlagNames
		}
	}

	fs = commandFlags(fs, specific, false)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	options := encryptionCommand{command: cmd, input: *input, output: *output, key: *keyFile, transport: *transport, scope: *scope, algorithm: *algorithm, wrap: *wrap, keyName: *name, oaepHash: *oaepHash, labelFile: *labelFile, maximum: *maximum, id: *id, idName: document.Name{Space: *idNS, Local: *idAttr}, index: *index, resources: *resources, uri: *uri, cipherOut: *cipherOut, keyFlags: keyFlags}

	return options.run(ctx, stdin, stdout)
}

type encryptionOperations struct {
	encryptBytes                                                   func([]byte) (*document.Document, error)
	decryptBytes                                                   func(*document.Document) ([]byte, error)
	encryptDocument, decryptDocument                               func(*document.Document) (*document.Document, error)
	encryptElement, decryptElement, encryptContent, decryptContent func(*document.Document, document.Element) (*document.Document, document.Element, error)
}

type encryptionCommand struct {
	command, input, output, key, transport    string
	scope, algorithm, wrap, keyName, oaepHash string
	labelFile, id, resources, uri, cipherOut  string
	idName                                    document.Name
	maximum, index                            int
	keyFlags                                  *privateKeyFlags
}

func (c encryptionCommand) run(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if c.index < -1 {
		return usageError("-index must be nonnegative when supplied")
	}

	if c.command == "externalize" {
		return c.externalize(ctx, stdin, stdout)
	}

	opt, err := c.options(ctx)
	if err != nil {
		return err
	}

	operations, closeKey, err := c.operations(ctx, opt)
	if err != nil {
		return err
	}
	defer closeKey()

	if c.command == nameEncrypt && c.scope == scopeBytes {
		raw, err := readInputContext(ctx, c.input, stdin, min(execution(ctx).xml.MaxBytes, c.maximum))
		if err != nil {
			return err
		}

		result, err := operations.encryptBytes(raw)
		if err != nil {
			return err
		}

		return documentOutput(ctx, c.output, stdout, result)
	}

	doc, err := readDocument(ctx, c.input, stdin)
	if err != nil {
		return err
	}

	if c.command == nameDecrypt && c.scope == scopeBytes {
		raw, err := operations.decryptBytes(doc)
		if err != nil {
			return err
		}

		return writeOutputContext(ctx, c.output, stdout, raw)
	}

	result, err := c.xmlOperation(doc, operations)
	if err != nil {
		return err
	}

	return documentOutput(ctx, c.output, stdout, result)
}

func (c encryptionCommand) options(ctx context.Context) (xmlenc.Options, error) {
	opt := xmlenc.Options{DataAlgorithm: c.algorithm, MaxPlaintextBytes: c.maximum, XMLLimits: execution(ctx).xml}
	if c.scope != scopeBytes && c.scope != "document" && c.scope != scopeElement && c.scope != "content" {
		return opt, usageError("-scope must be bytes, document, element or content")
	}

	if c.maximum < 1 || c.maximum > 32<<20 {
		return opt, usageError("-max-plaintext-bytes must be 1..33554432")
	}

	if c.key == "" {
		return opt, usageError("-key is required")
	}

	if c.transport != nameRSA && c.transport != "wrap" && c.transport != transportDirect {
		return opt, usageError("-transport must be rsa, wrap or direct")
	}

	if c.transport != transportDirect && c.keyName != "" {
		return opt, usageError("-key-name requires -transport direct")
	}

	if c.transport != nameRSA {
		if c.labelFile != "" || c.oaepHash != "sha256" {
			return opt, usageError("OAEP options require -transport rsa")
		}
	} else {
		h, err := parseHash(c.oaepHash)
		if err != nil {
			return opt, err
		}

		opt.OAEP = &xmlenc.OAEPParameters{Hash: h}
		if c.labelFile != "" {
			opt.OAEP.Label, err = readInputContext(ctx, c.labelFile, nil, 1024)
			if err != nil {
				return opt, err
			}
		}
	}

	if c.resources != "" {
		if c.command != nameDecrypt {
			return opt, usageError("-resources is for decryption only")
		}

		entries, resolver, err := loadResourcesContext(ctx, c.resources)
		if err != nil {
			return opt, err
		}

		if err := validateResourceAllowlist(entries); err != nil {
			return opt, err
		}

		if len(entries) != 1 {
			return opt, usageError("cipher manifest must contain exactly one URI/path entry")
		}

		opt.External = &xmlenc.ExternalCipherReference{URI: entries[0].URI, Resolver: resolver, MaxBytes: execution(ctx).xml.MaxBytes}
	}

	return opt, nil
}

func (c encryptionCommand) selection(doc *document.Document) (document.Element, error) {
	if c.command == nameEncrypt {
		if c.id == "" {
			return doc.Root(), nil
		}

		return selectElement(doc, c.idName, c.id, -1, document.Name{})
	}

	return selectElement(doc, c.idName, c.id, c.index, document.Name{Space: xmlenc.Namespace, Local: "EncryptedData"})
}

func (c encryptionCommand) operations(ctx context.Context, opt xmlenc.Options) (encryptionOperations, func(), error) {
	closeKey := func() {}

	if c.transport == nameRSA {
		var (
			public  *rsa.PublicKey
			private crypto.Decrypter
		)

		if c.command == nameEncrypt {
			key, err := loadPublicContext(ctx, c.key)
			if err != nil {
				return encryptionOperations{}, closeKey, err
			}

			var ok bool

			public, ok = key.(*rsa.PublicKey)
			if !ok {
				return encryptionOperations{}, closeKey, usageError("RSA encryption requires an RSA public key")
			}
		} else {
			key, err := loadPrivateConfigured(ctx, c.key, c.keyFlags)
			if err != nil {
				return encryptionOperations{}, closeKey, err
			}

			var ok bool

			private, ok = key.(crypto.Decrypter)
			if !ok {
				return encryptionOperations{}, closeKey, usageError("RSA decryption requires an RSA private key")
			}
		}

		return rsaOperations(ctx, public, private, opt), closeKey, nil
	}

	if c.keyFlags.format != namePlain || c.keyFlags.passwordFile != "" {
		return encryptionOperations{}, closeKey, usageError("private key format/password flags do not apply to raw AES keys")
	}

	secret, err := readInputContext(ctx, c.key, nil, 32)
	if err != nil {
		return encryptionOperations{}, closeKey, err
	}

	closeKey = func() { clear(secret) }
	if c.transport == transportDirect {
		return directOperations(ctx, secret, xmlenc.SymmetricOptions{Data: opt, KeyName: c.keyName}), closeKey, nil
	}

	return wrapOperations(ctx, secret, xmlenc.KeyWrapOptions{Data: opt, KeyAlgorithm: c.wrap}), closeKey, nil
}

//nolint:dupl // These adapters bind distinct statically typed key and options APIs.
func rsaOperations(ctx context.Context, public *rsa.PublicKey, private crypto.Decrypter, opt xmlenc.Options) encryptionOperations {
	return encryptionOperations{
		encryptBytes: func(b []byte) (*document.Document, error) { return xmlenc.EncryptBytes(ctx, b, public, opt) }, decryptBytes: func(d *document.Document) ([]byte, error) { return xmlenc.DecryptBytes(ctx, d, private, opt) }, encryptDocument: func(d *document.Document) (*document.Document, error) {
			return xmlenc.EncryptDocument(ctx, d, public, opt)
		}, decryptDocument: func(d *document.Document) (*document.Document, error) {
			return xmlenc.DecryptDocument(ctx, d, private, opt)
		},
		encryptElement: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.EncryptElement(ctx, d, e, public, opt)
		}, decryptElement: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.DecryptElement(ctx, d, e, private, opt)
		}, encryptContent: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.EncryptContent(ctx, d, e, public, opt)
		}, decryptContent: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.DecryptContent(ctx, d, e, private, opt)
		},
	}
}

//nolint:dupl // These adapters bind distinct statically typed key and options APIs.
func directOperations(ctx context.Context, key []byte, opt xmlenc.SymmetricOptions) encryptionOperations {
	return encryptionOperations{
		encryptBytes: func(b []byte) (*document.Document, error) { return xmlenc.EncryptBytesWithKey(ctx, b, key, opt) }, decryptBytes: func(d *document.Document) ([]byte, error) { return xmlenc.DecryptBytesWithKey(ctx, d, key, opt) }, encryptDocument: func(d *document.Document) (*document.Document, error) {
			return xmlenc.EncryptDocumentWithKey(ctx, d, key, opt)
		}, decryptDocument: func(d *document.Document) (*document.Document, error) {
			return xmlenc.DecryptDocumentWithKey(ctx, d, key, opt)
		},
		encryptElement: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.EncryptElementWithKey(ctx, d, e, key, opt)
		}, decryptElement: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.DecryptElementWithKey(ctx, d, e, key, opt)
		}, encryptContent: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.EncryptContentWithKey(ctx, d, e, key, opt)
		}, decryptContent: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.DecryptContentWithKey(ctx, d, e, key, opt)
		},
	}
}

//nolint:dupl // These adapters bind distinct statically typed key and options APIs.
func wrapOperations(ctx context.Context, key []byte, opt xmlenc.KeyWrapOptions) encryptionOperations {
	return encryptionOperations{
		encryptBytes: func(b []byte) (*document.Document, error) {
			return xmlenc.EncryptBytesWithKeyWrap(ctx, b, key, opt)
		}, decryptBytes: func(d *document.Document) ([]byte, error) {
			return xmlenc.DecryptBytesWithKeyWrap(ctx, d, key, opt)
		}, encryptDocument: func(d *document.Document) (*document.Document, error) {
			return xmlenc.EncryptDocumentWithKeyWrap(ctx, d, key, opt)
		}, decryptDocument: func(d *document.Document) (*document.Document, error) {
			return xmlenc.DecryptDocumentWithKeyWrap(ctx, d, key, opt)
		},
		encryptElement: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.EncryptElementWithKeyWrap(ctx, d, e, key, opt)
		}, decryptElement: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.DecryptElementWithKeyWrap(ctx, d, e, key, opt)
		}, encryptContent: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.EncryptContentWithKeyWrap(ctx, d, e, key, opt)
		}, decryptContent: func(d *document.Document, e document.Element) (*document.Document, document.Element, error) {
			return xmlenc.DecryptContentWithKeyWrap(ctx, d, e, key, opt)
		},
	}
}

func (c encryptionCommand) externalize(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	if c.uri == "" || c.cipherOut == "" || c.cipherOut == "-" {
		return usageError("externalize requires -uri and a local -cipher-out")
	}

	if c.output != "-" && samePath(c.cipherOut, c.output) {
		return usageError("ciphertext and XML outputs must be distinct")
	}

	if c.input != "-" && samePath(c.input, c.cipherOut) {
		return usageError("ciphertext output must not overwrite the input XML")
	}

	doc, err := readDocument(ctx, c.input, stdin)
	if err != nil {
		return err
	}

	selected, err := selectElement(doc, c.idName, c.id, c.index, document.Name{Space: xmlenc.Namespace, Local: "EncryptedData"})
	if err != nil {
		return err
	}

	result, _, cipher, err := xmlenc.ExternalizeCiphertext(ctx, doc, selected, c.uri)
	if err != nil {
		return err
	}

	raw, err := result.XML(ctx)
	if err != nil {
		return err
	}

	if len(raw) > execution(ctx).output || len(cipher) > execution(ctx).output {
		return errors.New("externalized output exceeds byte limit")
	}

	if err := writeOutputContext(ctx, c.cipherOut, stdout, cipher); err != nil {
		return err
	}

	return writeOutputContext(ctx, c.output, stdout, raw)
}

func samePath(a, b string) bool {
	x, e := filepath.Abs(a)
	if e != nil {
		return false
	}

	y, e := filepath.Abs(b)

	return e == nil && x == y
}

func (c encryptionCommand) xmlOperation(doc *document.Document, operations encryptionOperations) (*document.Document, error) {
	if c.scope == "document" {
		if c.command == nameEncrypt {
			return operations.encryptDocument(doc)
		}

		return operations.decryptDocument(doc)
	}

	selected, err := c.selection(doc)
	if err != nil {
		return nil, err
	}

	operation := operations.decryptContent
	if c.command == nameEncrypt {
		operation = operations.encryptContent
		if c.scope == scopeElement {
			operation = operations.encryptElement
		}
	} else if c.scope == scopeElement {
		operation = operations.decryptElement
	}

	result, _, err := operation(doc, selected)

	return result, err
}
