// Command preservation demonstrates the corresponding XML security API.
// This example demonstrates the CLOSED, current-time XAdES preservation profile.
// It is not historical ETSI validation and does not emulate a trusted TSA clock.

package main

import (
	"bytes"
	"context"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/examples/internal/democert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	c, e := democert.New(now)
	if e != nil {
		return e
	}

	policy := asn1.ObjectIdentifier{1, 2, 3, 4, 1}

	tsa, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy}})
	if e != nil {
		return e
	}

	evidence := pki.Evidence{CRLs: [][]byte{c.CRL}}
	sequence := int64(0)
	transport := timestamp.TransportFunc(func(ctx context.Context, request []byte) (io.ReadCloser, error) {
		sequence++

		response, e := timestamp.IssueResponse(ctx, request, c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: policy, SerialNumber: big.NewInt(sequence), GenTime: now.Add(time.Duration(sequence) * time.Second), ExtraCertificates: [][]byte{c.Root.Raw}})
		if e != nil {
			return nil, e
		}

		return io.NopCloser(bytes.NewReader(response)), nil
	})

	input, e := document.Parse(ctx, []byte(`<Invoice ID="invoice-1"><Total>125.00</Total></Invoice>`), document.DefaultLimits())
	if e != nil {
		return e
	}

	basic, _, e := xades.SignBasicEnveloped(ctx, input, c.SignerKey, c.Signer.Raw, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: now})
	if e != nil {
		return e
	}

	at := now.Add(10 * time.Second)

	timed, _, e := xades.AddSignatureTimestamp(ctx, basic, xmldsig.Signatures(basic)[0], c.Signer.Raw, transport, xades.AddTimestampOptions{Validation: xades.TimedOptions{TSA: tsa, At: at, Evidence: evidence}})
	if e != nil {
		return e
	}

	validator, e := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, TSA: tsa, MinimumLevel: xades.LevelLTA})
	if e != nil {
		return e
	}

	lt, _, e := validator.EmbedValidationMaterial(ctx, timed, xmldsig.Signatures(timed)[0], c.Signer.Raw, at, xades.ValidationEvidence{Signer: evidence, TSA: evidence})
	if e != nil {
		return e
	}

	archived, _, e := validator.AddArchiveTimestamp(ctx, lt, xmldsig.Signatures(lt)[0], c.Signer.Raw, at, transport, xades.AddArchiveOptions{})
	if e != nil {
		return e
	}
	// Serialize and reparse before the final, fully offline validation. The only
	// external certificate material is the explicitly configured trust anchor.
	raw, e := archived.XML(ctx)
	if e != nil {
		return e
	}

	parsed, e := document.Parse(ctx, raw, document.DefaultLimits())
	if e != nil {
		return e
	}

	result, e := validator.ValidateEnveloped(ctx, parsed, xmldsig.Signatures(parsed)[0], c.Signer.Raw, at, xades.ValidationEvidence{})
	if e != nil {
		return e
	}

	fmt.Printf("profile=%s level=%s timestamps=%d archives=%d signer-revocation=%s\n", result.Profile(), result.Level(), len(result.Timestamps()), len(result.ArchiveTimestamps()), result.SignerTrust().RevocationStatus())
	fmt.Println("historical-validation=not-performed; keys-and-TSA-clock=demonstration-only")

	return nil
}
