// Command nextprobe is a private interoperability test adapter.
// nextprobe is TEST tooling only. It reads paths supplied by the local
// interoperability harness; it is not a supported CLI or a network service.

package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

type task struct {
	Mode, Key, Certificate, Root, CRL, Input, Method, Relay, At string
	DataAlgorithm, KeyAlgorithm                                 string
	Selection                                                   string
	XML                                                         bool
	OAEPHash, CipherURI, Resource, KeyName                      string
	OAEPLabel                                                   []byte
}

type output struct {
	Data   []byte `json:"data,omitempty"`
	Text   string `json:"text,omitempty"`
	Report any    `json:"report,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	var t task

	d := json.NewDecoder(os.Stdin)
	d.DisallowUnknownFields()

	o := output{}
	if e := d.Decode(&t); e != nil {
		o.Error = e.Error()
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		var e error

		o, e = process(ctx, t)

		cancel()

		if e != nil {
			o.Error = e.Error()
		}
	}

	if e := json.NewEncoder(os.Stdout).Encode(o); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func read(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- The local interoperability harness supplies fixture paths.
}

func private(path string) (crypto.Signer, error) {
	b, err := read(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)

	return keys.ParsePrivate(b, keys.Limits{})
}

func public(path string) (crypto.PublicKey, error) {
	b, err := read(path)
	if err != nil {
		return nil, err
	}

	return keys.ParsePublic(b, keys.Limits{})
}

func encryptionOptions(t task) (xmlenc.Options, error) {
	opts := xmlenc.Options{DataAlgorithm: t.DataAlgorithm}
	if t.OAEPHash != "" || len(t.OAEPLabel) != 0 {
		var hash crypto.Hash

		switch t.OAEPHash {
		case "", "256":
			hash = crypto.SHA256
		case "384":
			hash = crypto.SHA384
		case "512":
			hash = crypto.SHA512
		default:
			return opts, errors.New("OAEP hash")
		}

		opts.OAEP = &xmlenc.OAEPParameters{Hash: hash, Label: t.OAEPLabel}
	}

	if t.Resource != "" {
		opts.External = &xmlenc.ExternalCipherReference{URI: t.CipherURI, Resolver: xmlenc.CipherResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
			if uri != t.CipherURI {
				return nil, errors.New("unexpected resource URI")
			}

			if err := ctx.Err(); err != nil {
				return nil, err
			}

			return os.Open(t.Resource) // Exact test-owned path; no URI-to-path conversion.
		})}
	}

	return opts, nil
}

func process(ctx context.Context, t task) (o output, err error) {
	b, e := read(t.Input)
	if e != nil {
		return o, e
	}

	options, e := encryptionOptions(t)
	if e != nil {
		return o, e
	}

	var doc *document.Document
	if t.Mode != "redirect-verify" && t.Mode != "encrypt" && t.Mode != nameEncryptWrap && t.Mode != nameEncryptDirect && t.Mode != "pki-verify" {
		doc, e = document.Parse(ctx, b, document.DefaultLimits())
		if e != nil {
			return o, e
		}
	}

	switch t.Mode {
	case "encrypt-element", "decrypt-element", "encrypt-element-wrap", "decrypt-element-wrap", "encrypt-content", "decrypt-content", "encrypt-content-wrap", "decrypt-content-wrap":
		return probeElement(ctx, t, doc, options)
	case "externalize":
		return probeExternalize(ctx, t, doc)
	case nameEncryptDirect, "decrypt-direct":
		return probeSymmetric(ctx, t, b, doc, options)
	case "xades-sign":
		return probeXAdESSign(ctx, t, doc)
	case "xades-verify":
		return probeXAdESVerify(ctx, t, doc)
	case "encrypt":
		return probeEncrypt(ctx, t, b, options)
	case "decrypt":
		return probeDecrypt(ctx, t, doc, options)
	case nameEncryptWrap, "decrypt-wrap":
		return probeKeyWrap(ctx, t, b, doc, options)
	case "redirect-sign":
		return probeRedirectSign(ctx, t, doc)
	case "redirect-verify":
		return probeRedirectVerify(ctx, t, b)
	case "pki-verify":
		return probePKIVerify(ctx, t, b)
	default:
		return o, errors.New("unknown mode")
	}
}

func probeElement(ctx context.Context, t task, doc *document.Document, options xmlenc.Options) (o output, e error) {
	selected := selectElement(doc.Root(), t.Selection)
	if !selected.Valid() {
		return o, errors.New("selected element missing")
	}

	var result *document.Document

	content := strings.Contains(t.Mode, "-content")
	if strings.HasSuffix(t.Mode, "-wrap") {
		kek, err := read(t.Key)
		if err != nil {
			return o, err
		}
		defer clear(kek)

		kw := xmlenc.KeyWrapOptions{Data: options, KeyAlgorithm: t.KeyAlgorithm}
		switch t.Mode {
		case "encrypt-content-wrap":
			result, _, e = xmlenc.EncryptContentWithKeyWrap(ctx, doc, selected, kek, kw)
		case "decrypt-content-wrap":
			result, _, e = xmlenc.DecryptContentWithKeyWrap(ctx, doc, selected, kek, kw)
		case "encrypt-element-wrap":
			result, _, e = xmlenc.EncryptElementWithKeyWrap(ctx, doc, selected, kek, kw)
		default:
			result, _, e = xmlenc.DecryptElementWithKeyWrap(ctx, doc, selected, kek, kw)
		}
	} else if strings.HasPrefix(t.Mode, "encrypt-") {
		public, err := public(t.Key)
		if err != nil {
			return o, err
		}

		rsaKey, ok := public.(*rsa.PublicKey)
		if !ok {
			return o, errors.New("RSA")
		}

		if content {
			result, _, e = xmlenc.EncryptContent(ctx, doc, selected, rsaKey, options)
		} else {
			result, _, e = xmlenc.EncryptElement(ctx, doc, selected, rsaKey, options)
		}
	} else {
		key, err := private(t.Key)
		if err != nil {
			return o, err
		}

		decrypter, ok := key.(crypto.Decrypter)
		if !ok {
			return o, errors.New("decrypter")
		}

		if content {
			result, _, e = xmlenc.DecryptContent(ctx, doc, selected, decrypter, options)
		} else {
			result, _, e = xmlenc.DecryptElement(ctx, doc, selected, decrypter, options)
		}
	}

	if e != nil {
		return o, e
	}

	o.Data, e = result.XML(ctx)

	return o, e
}

func probeExternalize(ctx context.Context, t task, doc *document.Document) (o output, e error) {
	selected := doc.Root()
	if t.Selection != "" {
		selected = selectElement(doc.Root(), t.Selection)
	}

	result, _, body, err := xmlenc.ExternalizeCiphertext(ctx, doc, selected, t.CipherURI)
	if err != nil {
		return o, err
	}

	if err := os.WriteFile(t.Resource, body, 0o600); err != nil {
		return o, err
	}

	o.Data, e = result.XML(ctx)

	return o, e
}

func probeSymmetric(ctx context.Context, t task, b []byte, doc *document.Document, options xmlenc.Options) (o output, e error) {
	secret, err := read(t.Key)
	if err != nil {
		return o, err
	}
	defer clear(secret)

	opts := xmlenc.SymmetricOptions{Data: options, KeyName: t.KeyName}
	if t.Mode == nameEncryptDirect {
		var encrypted *document.Document

		if t.XML {
			doc, err = document.Parse(ctx, b, document.DefaultLimits())
			if err != nil {
				return o, err
			}

			encrypted, err = xmlenc.EncryptDocumentWithKey(ctx, doc, secret, opts)
		} else {
			encrypted, err = xmlenc.EncryptBytesWithKey(ctx, b, secret, opts)
		}

		if err != nil {
			return o, err
		}

		o.Data, e = encrypted.XML(ctx)
	} else if t.XML {
		plain, err := xmlenc.DecryptDocumentWithKey(ctx, doc, secret, opts)
		if err != nil {
			return o, err
		}

		o.Data, e = plain.XML(ctx)
	} else {
		o.Data, e = xmlenc.DecryptBytesWithKey(ctx, doc, secret, opts)
	}

	return o, e
}

func probeXAdESSign(ctx context.Context, t task, doc *document.Document) (o output, e error) {
	k, e := private(t.Key)
	if e != nil {
		return o, e
	}

	der, e := read(t.Certificate)
	if e != nil {
		return o, e
	}

	at, e := time.Parse(time.RFC3339, t.At)
	if e != nil {
		return o, e
	}

	d, _, e := xades.SignBasicEnveloped(ctx, doc, k, der, xades.SignOptions{SignatureMethod: t.Method, ClaimedSigningTime: at, Policy: xmldsig.ModernPolicy()})
	if e != nil {
		return o, e
	}

	o.Data, e = d.XML(ctx)

	return o, e
}

func probeXAdESVerify(ctx context.Context, t task, doc *document.Document) (o output, e error) {
	der, e := read(t.Certificate)
	if e != nil {
		return o, e
	}

	sigs := xmldsig.Signatures(doc)
	if len(sigs) != 1 {
		return o, errors.New("signature count")
	}

	r, e := xades.VerifyBasicEnveloped(ctx, doc, sigs[0], der, xades.VerifyOptions{Policy: xmldsig.ModernPolicy()})
	if e != nil {
		return o, e
	}

	o.Report = map[string]any{"mime_type": r.MIMEType(), "claimed_time": r.ClaimedSigningTime(), "root_covered": r.Signature().CoversElement(doc.Root()), "references": len(r.Signature().References())}

	return o, nil
}

func probeEncrypt(ctx context.Context, t task, b []byte, options xmlenc.Options) (o output, e error) {
	var doc *document.Document

	k, e := public(t.Key)
	if e != nil {
		return o, e
	}

	rsaKey, ok := k.(*rsa.PublicKey)
	if !ok {
		return o, errors.New("RSA")
	}

	var encrypted *document.Document

	if t.XML {
		doc, e = document.Parse(ctx, b, document.DefaultLimits())
		if e != nil {
			return o, e
		}

		encrypted, e = xmlenc.EncryptDocument(ctx, doc, rsaKey, options)
	} else {
		encrypted, e = xmlenc.EncryptBytes(ctx, b, rsaKey, options)
	}

	if e != nil {
		return o, e
	}

	o.Data, e = encrypted.XML(ctx)

	return o, e
}

func probeDecrypt(ctx context.Context, t task, doc *document.Document, options xmlenc.Options) (o output, e error) {
	k, e := private(t.Key)
	if e != nil {
		return o, e
	}

	dec, ok := k.(crypto.Decrypter)
	if !ok {
		return o, errors.New("decrypter")
	}

	if t.XML {
		d, e := xmlenc.DecryptDocument(ctx, doc, dec, options)
		if e != nil {
			return o, e
		}

		o.Data, e = d.XML(ctx)

		return o, e
	}

	o.Data, e = xmlenc.DecryptBytes(ctx, doc, dec, options)

	return o, e
}

func probeKeyWrap(ctx context.Context, t task, b []byte, doc *document.Document, dataOptions xmlenc.Options) (o output, e error) {
	kek, err := read(t.Key)
	if err != nil {
		return o, err
	}
	defer clear(kek)

	options := xmlenc.KeyWrapOptions{
		Data:         dataOptions,
		KeyAlgorithm: t.KeyAlgorithm,
	}
	if t.Mode == nameEncryptWrap {
		var encrypted *document.Document

		if t.XML {
			doc, err = document.Parse(ctx, b, document.DefaultLimits())
			if err != nil {
				return o, err
			}

			encrypted, err = xmlenc.EncryptDocumentWithKeyWrap(ctx, doc, kek, options)
		} else {
			encrypted, err = xmlenc.EncryptBytesWithKeyWrap(ctx, b, kek, options)
		}

		if err != nil {
			return o, err
		}

		o.Data, err = encrypted.XML(ctx)

		return o, err
	}

	if t.XML {
		plaintext, err := xmlenc.DecryptDocumentWithKeyWrap(ctx, doc, kek, options)
		if err != nil {
			return o, err
		}

		o.Data, err = plaintext.XML(ctx)

		return o, err
	}

	o.Data, err = xmlenc.DecryptBytesWithKeyWrap(ctx, doc, kek, options)

	return o, err
}

func probeRedirectSign(ctx context.Context, t task, doc *document.Document) (o output, e error) {
	k, e := private(t.Key)
	if e != nil {
		return o, e
	}

	o.Text, e = binding.SignRedirect(ctx, doc, binding.Request, &t.Relay, k, binding.Options{SignatureMethod: t.Method, Policy: xmldsig.ModernPolicy()})

	return o, e
}

func probeRedirectVerify(ctx context.Context, t task, b []byte) (o output, e error) {
	k, e := public(t.Key)
	if e != nil {
		return o, e
	}

	r, e := binding.VerifyRedirect(ctx, string(b), k, binding.Options{Policy: xmldsig.ModernPolicy()})
	if e != nil {
		return o, e
	}

	o.Data, e = r.Document().XML(ctx)
	relay, present := r.RelayState()
	o.Report = map[string]any{"relay": relay, "has_relay": present, "kind": r.Kind()}

	return o, e
}

func probePKIVerify(ctx context.Context, t task, b []byte) (o output, e error) {
	root, e := read(t.Root)
	if e != nil {
		return o, e
	}

	crl, e := read(t.CRL)
	if e != nil {
		return o, e
	}

	v, e := pki.NewVerifier(pki.Config{Roots: [][]byte{root}, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, Revocation: pki.RequireCRL})
	if e != nil {
		return o, e
	}

	at, e := time.Parse(time.RFC3339, t.At)
	if e != nil {
		return o, e
	}

	_, r, e := v.Verify(ctx, b, at, pki.Evidence{CRLs: [][]byte{crl}})
	o.Report = r

	return o, e
}

// Local generated inputs choose a unique element by local name. This is test
// tooling, not a production selection or trust rule; public APIs require handles.
func selectElement(root document.Element, local string) document.Element {
	if root.Name().Local == local {
		return root
	}

	for _, child := range root.Children() {
		if found := selectElement(child, local); found.Valid() {
			return found
		}
	}

	return document.Element{}
}
