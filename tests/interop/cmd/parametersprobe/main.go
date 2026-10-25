// Command parametersprobe is a private interoperability test adapter.
// Test harness only. Private keys enter over stdin and are never persisted.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

type task struct {
	Mode, Method                                string
	Hash, MGF, Salt, Bits                       int
	DefaultParams                               bool
	Input, SPKI, Private, Secret, Value, Digest []byte
}

type answer struct {
	Data          []byte                      `json:"data,omitempty"`
	Valid         bool                        `json:"valid"`
	Error         string                      `json:"error,omitempty"`
	Report        *xmldsig.VerificationReport `json:"report,omitempty"`
	ProviderCalls int                         `json:"provider_calls,omitempty"`
}

func main() {
	in := json.NewDecoder(os.Stdin)
	out := json.NewEncoder(os.Stdout)

	for {
		var t task
		if err := in.Decode(&t); err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, err)
			}

			return
		}

		a, err := run(t)
		if err != nil {
			a.Error = err.Error()
		}

		if err = out.Encode(a); err != nil {
			return
		}
	}
}

func hash(bits int) crypto.Hash {
	switch bits {
	case 256:
		return crypto.SHA256
	case 384:
		return crypto.SHA384
	case 512:
		return crypto.SHA512
	}

	return 0
}

func params(t task) xmldsig.SignatureParameters {
	if t.Method == xmldsig.RSAPSS {
		if t.DefaultParams {
			return xmldsig.SignatureParameters{}
		}

		return xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: hash(t.Hash), MGFHash: hash(t.MGF), SaltLength: t.Salt, TrailerField: 1}}
	}

	return xmldsig.SignatureParameters{HMACOutputLength: t.Bits}
}

func run(t task) (a answer, err error) {
	ctx := context.Background()
	isMAC := t.Method != xmldsig.RSAPSS

	p := xmldsig.ParameterizedPolicy()
	if isMAC {
		p = xmldsig.HMACPolicy()
		p.AllowHMACTruncation = true
	}

	opt := xmldsig.SignatureOptions{Policy: p, ExpectedURIs: []string{"#a", "#b"}}

	var key crypto.PublicKey
	if !isMAC {
		key, err = x509.ParsePKIXPublicKey(t.SPKI)
		if err != nil {
			return a, err
		}

		if _, ok := key.(*rsa.PublicKey); !ok {
			return a, errors.New("RSA expected")
		}
	}

	if returned0, returned1, matched := runMode(ctx, &t, &a, isMAC, &opt, key); matched {
		return returned0, returned1
	}

	var (
		draft    *document.Document
		selected document.Element
	)

	switch t.Mode {
	case "provider-sign":
		draft, err = document.Parse(ctx, t.Input, document.DefaultLimits())
		if err != nil {
			return a, err
		}

		selected = draft.Root()
	case "sign":
		first, second := "independent payload α", "second payload β"

		draft, selected, err = xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{ID: "s", SignatureMethod: t.Method, SignatureParameters: params(t), References: []xmldsig.ReferenceTemplate{{URI: "#a", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}, {URI: "#b", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []xmldsig.ObjectTemplate{{ID: "a", Text: &first}, {ID: "b", Text: &second}}})
		if err != nil {
			return a, err
		}
	default:
		return a, fmt.Errorf("unknown mode %q", t.Mode)
	}

	var signed *document.Document
	if isMAC {
		signed, err = xmldsig.SignHMACTemplate(ctx, draft, selected, t.Secret, xmldsig.TemplateSignOptions{Validation: opt})
	} else {
		var (
			signer   crypto.Signer
			prepared *preparedSigner
		)
		if t.Mode == "provider-sign" {
			prepared = &preparedSigner{key: key, signature: t.Value, digest: t.Digest, expected: *params(t).PSS}
			signer = prepared
		} else {
			private, e := x509.ParsePKCS8PrivateKey(t.Private)
			if e != nil {
				return a, e
			}

			var ok bool

			signer, ok = private.(crypto.Signer)
			if !ok {
				return a, errors.New("not a signer")
			}
		}

		signed, err = xmldsig.SignTemplate(ctx, draft, selected, signer, xmldsig.TemplateSignOptions{Validation: opt})

		if prepared != nil {
			a.ProviderCalls = prepared.calls
		}
	}

	if err != nil {
		return a, err
	}

	a.Data, err = signed.XML(ctx)
	a.Valid = err == nil

	return a, err
}

func runMode(ctx context.Context, t *task, a *answer, isMAC bool, opt *xmldsig.SignatureOptions, key crypto.PublicKey) (returned0 answer, returned1 error, matched bool) {
	if t.Mode == "verify" {
		doc, e := document.Parse(ctx, t.Input, document.DefaultLimits())
		if e != nil {
			return *a, e, true
		}

		if isMAC {
			r, report, e := xmldsig.VerifyHMACSignatureDetailed(ctx, doc, doc.Root(), t.Secret, *opt)
			a.Valid = r != nil && e == nil
			a.Report = report

			return *a, e, true
		}

		r, report, e := xmldsig.VerifySignatureDetailed(ctx, doc, doc.Root(), key, *opt)
		a.Valid = r != nil && e == nil
		a.Report = report

		return *a, e, true
	}

	return
}

type preparedSigner struct {
	key               crypto.PublicKey
	signature, digest []byte
	expected          xmldsig.PSSParameters
	calls             int
}

func (s *preparedSigner) Public() crypto.PublicKey { return s.key }

func (s *preparedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unexpected standard signing operation")
}

func (s *preparedSigner) SignPSS(ctx context.Context, _ io.Reader, d []byte, p xmldsig.PSSParameters) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.calls++
	if p != s.expected || !bytes.Equal(d, s.digest) {
		return nil, errors.New("independent precomputed signature input differs")
	}

	return bytes.Clone(s.signature), nil
}
