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
	Mode          string
	Method        string
	Hash          int
	MGF           int
	Salt          int
	Bits          int
	DefaultParams bool
	Input         []byte
	SPKI          []byte
	Private       []byte
	Secret        []byte
	Value         []byte
	Digest        []byte
}

type answer struct {
	Data          []byte                      `json:"data,omitempty"`
	Valid         bool                        `json:"valid"`
	Report        *xmldsig.VerificationReport `json:"report,omitempty"`
	ProviderCalls int                         `json:"provider_calls,omitempty"`
}

type reply struct {
	answer
	Error string `json:"error,omitempty"`
}

func main() {
	if err := serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(input)
	encoder := json.NewEncoder(output)

	for {
		var t task
		if err := decoder.Decode(&t); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return err
		}

		result, err := run(t)

		response := reply{answer: result}
		if err != nil {
			response.Error = err.Error()
		}

		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
}

func hashFromBits(bits int) crypto.Hash {
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

func signatureParameters(t task) xmldsig.SignatureParameters {
	if t.Method == xmldsig.RSAPSS {
		if t.DefaultParams {
			return xmldsig.SignatureParameters{}
		}

		return xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: hashFromBits(t.Hash), MGFHash: hashFromBits(t.MGF), SaltLength: t.Salt, TrailerField: 1}}
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

	if !isMAC && !t.DefaultParams && (t.Hash != 0 && hashFromBits(t.Hash) == 0 || t.MGF != 0 && hashFromBits(t.MGF) == 0) {
		return a, fmt.Errorf("%w: unsupported hash bit selector", xmldsig.ErrAlgorithm)
	}

	if t.Mode == "verify" {
		return verify(ctx, t, isMAC, opt, key)
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

		draft, selected, err = xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{ID: "s", SignatureMethod: t.Method, SignatureParameters: signatureParameters(t), References: []xmldsig.ReferenceTemplate{{URI: "#a", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}, {URI: "#b", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []xmldsig.ObjectTemplate{{ID: "a", Text: &first}, {ID: "b", Text: &second}}})
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
			prepared = &preparedSigner{key: key, signature: t.Value, digest: t.Digest, expected: providerParameters(t)}
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

func verify(ctx context.Context, t task, isMAC bool, options xmldsig.SignatureOptions, key crypto.PublicKey) (answer, error) {
	doc, err := document.Parse(ctx, t.Input, document.DefaultLimits())
	if err != nil {
		return answer{}, err
	}

	if isMAC {
		result, report, err := xmldsig.VerifyHMACSignatureDetailed(ctx, doc, doc.Root(), t.Secret, options)
		return answer{Valid: result != nil && err == nil, Report: report}, err
	}

	result, report, err := xmldsig.VerifySignatureDetailed(ctx, doc, doc.Root(), key, options)

	return answer{Valid: result != nil && err == nil, Report: report}, err
}

type preparedSigner struct {
	key       crypto.PublicKey
	signature []byte
	digest    []byte
	expected  xmldsig.PSSParameters
	calls     int
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

// providerParameters mirrors the documented normalization observed by SignPSS.
func providerParameters(t task) xmldsig.PSSParameters {
	parameters := signatureParameters(t).PSS
	if parameters == nil {
		return xmldsig.PSSParameters{Hash: crypto.SHA256, MGFHash: crypto.SHA256, SaltLength: 32, TrailerField: 1}
	}

	expected := *parameters
	if expected.Hash == 0 {
		expected.Hash = crypto.SHA256
	}

	if expected.MGFHash == 0 {
		expected.MGFHash = expected.Hash
	}

	return expected
}
