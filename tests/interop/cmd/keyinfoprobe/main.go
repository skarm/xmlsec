// Command keyinfoprobe is a private interoperability test adapter.
// Interoperability harness only; not a production CLI. Keys are passed in memory
// over stdin. No private keys are written to disk by this program.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

type task struct {
	Mode        string
	Format      string
	Method      string
	Input       []byte
	SPKI        []byte
	Private     []byte
	Certificate []byte
}

type answer struct {
	Data  []byte   `json:"data,omitempty"`
	Keys  [][]byte `json:"keys,omitempty"`
	Valid bool     `json:"valid,omitempty"`
	Error string   `json:"error,omitempty"`
}

func main() {
	d := json.NewDecoder(os.Stdin)
	out := json.NewEncoder(os.Stdout)

	for {
		var t task
		if e := d.Decode(&t); e != nil {
			return
		}

		a, e := run(t)
		if e != nil {
			a.Error = e.Error()
		}

		if e = out.Encode(a); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
	}
}

func run(t task) (a answer, e error) {
	ctx := context.Background()

	var doc *document.Document
	if t.Mode == "parse" || t.Mode == "verify" {
		doc, e = document.Parse(ctx, t.Input, document.DefaultLimits())
		if e != nil {
			return a, e
		}
	}

	switch t.Mode {
	case "parse":
		r, e := keyinfo.Parse(ctx, doc, doc.Root(), keyinfo.Options{})
		if e != nil {
			return a, e
		}

		for _, c := range r.Candidates() {
			a.Keys = append(a.Keys, c.SPKI())
		}

		return a, nil
	case "build", "sign":
		return runEntries(ctx, &t, &a)
	case "verify":
		sigs := xmldsig.Signatures(doc)
		if len(sigs) != 1 {
			return a, errors.New("expected one signature")
		}

		fp := sha256.Sum256(t.SPKI)
		r, e := xmldsig.VerifySignatureWithKeyInfo(ctx, doc, sigs[0], xmldsig.KeyInfoVerifyOptions{Signature: xmldsig.SignatureOptions{Policy: xmldsig.ModernPolicy(), ExpectedURIs: []string{"#data"}}, SelectTrustedKey: func(_ context.Context, info *keyinfo.Result) (int, error) {
			for i, c := range info.Candidates() {
				h := sha256.Sum256(c.SPKI())
				if bytes.Equal(h[:], fp[:]) {
					return i, nil
				}
			}

			return -1, errors.New("pin mismatch")
		}})
		a.Valid = e == nil && r != nil

		return a, e
	default:
		return a, fmt.Errorf("unknown mode %q", t.Mode)
	}
}

func runEntries(ctx context.Context, t *task, a *answer) (answer, error) {
	key, e := x509.ParsePKIXPublicKey(t.SPKI)
	if e != nil {
		return *a, e
	}

	spec := keyinfo.Template{ID: "key-info", Names: []string{"  exact key name  "}}
	if len(t.Certificate) > 0 {
		spec.Certificates = [][]byte{t.Certificate}
	} else {
		spec.Keys = []keyinfo.PublicKeyValue{{Key: key, Format: keyinfo.KeyFormat(t.Format)}}
	}

	ki, e := keyinfo.Build(ctx, spec)
	if e != nil {
		return *a, e
	}

	if t.Mode == "build" {
		a.Data, e = ki.XML(ctx)
		return *a, e
	}

	p, e := x509.ParsePKCS8PrivateKey(t.Private)
	if e != nil {
		return *a, e
	}

	signer, ok := p.(crypto.Signer)
	if !ok {
		return *a, errors.New("not a signer")
	}

	text := "independent payload"

	draft, selected, e := xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{ID: "s", SignatureMethod: t.Method, KeyInfo: ki, References: []xmldsig.ReferenceTemplate{{URI: "#data", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []xmldsig.ObjectTemplate{{ID: "data", Text: &text}}})
	if e != nil {
		return *a, e
	}

	signed, e := xmldsig.SignTemplate(ctx, draft, selected, signer, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: xmldsig.ModernPolicy()}})
	if e != nil {
		return *a, e
	}

	a.Data, e = signed.XML(ctx)

	return *a, e
}
