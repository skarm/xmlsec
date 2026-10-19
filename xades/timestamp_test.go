package xades_test

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestTimestampAugmentation(t *testing.T) {
	c := testcert.New(t)
	base := basicDocument(t, c)
	before, _ := base.XML(t.Context())
	o := timeOptions(t, c)
	server := &localTSA{chain: c}

	for _, alg := range []string{c14n.Exclusive, c14n.Canonical10, c14n.Canonical11, c14n.ExclusiveWithComments, c14n.Canonical10WithComments, c14n.Canonical11WithComments} {
		t.Run(alg, func(t *testing.T) {
			d, r, e := xades.AddSignatureTimestamp(context.Background(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, server, xades.AddTimestampOptions{Validation: o, Canonicalization: alg, Request: timestamp.RequestOptions{Policy: tsaPolicy()}})
			if e != nil || d == nil || r == nil {
				t.Fatal(e)
			}

			unchanged, _ := base.XML(t.Context())
			if !bytes.Equal(before, unchanged) || len(r.Timestamps()) != 1 || !r.Basic().Signature().CoversElement(d.Root()) || r.Basic().Signature().CoversElement(base.Root()) {
				t.Fatal("snapshot/coverage")
			}

			if _, e := xades.VerifyBasicEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, xades.VerifyOptions{}); e == nil {
				t.Fatal("old profile silently broadened")
			}

			d2, r2, e := xades.AddSignatureTimestamp(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, server, xades.AddTimestampOptions{Validation: o, Request: timestamp.RequestOptions{Policy: tsaPolicy()}})
			if e != nil || d2 == nil || r2 == nil || len(r2.Timestamps()) != 2 {
				t.Fatal(e)
			}

			r2.Timestamps()[0] = nil
			if len(r2.Timestamps()) != 2 || r2.Timestamps()[0] == nil {
				t.Fatal("mutable result")
			}
		})
	}
}

func TestTimestampFailureNoPartialDocument(t *testing.T) {
	c := testcert.New(t)
	base := basicDocument(t, c)
	raw, _ := base.XML(t.Context())
	o := timeOptions(t, c)
	bad := &localTSA{chain: c, bad: true}

	d, r, e := xades.AddSignatureTimestamp(context.Background(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, bad, xades.AddTimestampOptions{Validation: o})
	if d != nil || r != nil || !errors.Is(e, timestamp.ErrBinding) {
		t.Fatal("mismatch accepted", e)
	}

	after, _ := base.XML(t.Context())
	if !bytes.Equal(raw, after) {
		t.Fatal("modified source")
	}

	good := &localTSA{chain: c}

	d, r, e = xades.AddSignatureTimestamp(context.Background(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, good, xades.AddTimestampOptions{Validation: o})
	if e != nil {
		t.Fatal(e)
	}

	b, _ := d.XML(t.Context())
	token := base64.StdEncoding.EncodeToString(r.Timestamps()[0].TokenDER())
	mut := bytes.Clone(r.Timestamps()[0].TokenDER())

	mut[len(mut)-1] ^= 1
	for _, tc := range []struct{ name, from, to string }{{"bad token", token, base64.StdEncoding.EncodeToString(mut)}, {"unsupported encoding", "<xades:EncapsulatedTimeStamp>", "<xades:EncapsulatedTimeStamp Encoding=\"urn:other\">"}, {"unsupported property", "SignatureTimeStamp", "OtherProperty"}, {"wrong canonicalization", `Algorithm="` + c14n.Exclusive + `"></ds:CanonicalizationMethod><xades:EncapsulatedTimeStamp>`, `Algorithm="` + c14n.Canonical10 + `"></ds:CanonicalizationMethod><xades:EncapsulatedTimeStamp>`}} {
		t.Run(tc.name, func(t *testing.T) {
			s := strings.ReplaceAll(string(b), tc.from, tc.to)
			if s == string(b) {
				t.Fatal("fixture replacement missing")
			}

			p, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}

			if rr, e := xades.VerifyTimedEnveloped(context.Background(), p, xmldsig.Signatures(p)[0], c.Leaf.Raw, o); rr != nil || e == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Invalid XML/signature is rejected before invoking the external TSA.
	p, e := document.Parse(t.Context(), bytes.Replace(raw, []byte(">123<"), []byte(">999<"), 1), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	calls := good.calls
	if dd, rr, e := xades.AddSignatureTimestamp(context.Background(), p, xmldsig.Signatures(p)[0], c.Leaf.Raw, good, xades.AddTimestampOptions{Validation: o}); dd != nil || rr != nil || e == nil || good.calls != calls {
		t.Fatal("TSA invoked before primary validation")
	}
}

func TestBaselineValidatorNoDowngrade(t *testing.T) {
	c := testcert.New(t)
	base := basicDocument(t, c)
	o := timeOptions(t, c)
	evidence := xades.ValidationEvidence{Signer: o.Evidence, TSA: o.Evidence}
	config := xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, TSA: o.TSA, MinimumLevel: xades.LevelBT}

	v, e := xades.NewValidator(config)
	if e != nil {
		t.Fatal(e)
	}

	if r, e := v.ValidateEnveloped(context.Background(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, testcert.Now(), evidence); r != nil || e == nil {
		t.Fatal("B-T downgraded to B-B")
	}

	d, _, e := xades.AddSignatureTimestamp(context.Background(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, &localTSA{chain: c}, xades.AddTimestampOptions{Validation: o})
	if e != nil {
		t.Fatal(e)
	}

	r, e := v.ValidateEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if e != nil || r.Level() != xades.LevelBT || r.SignerTrust().RevocationStatus() != pki.Valid {
		t.Fatal(e)
	}

	config.MinimumLevel = xades.LevelBB

	v, e = xades.NewValidator(config)
	if e != nil {
		t.Fatal(e)
	}

	r, e = v.ValidateEnveloped(context.Background(), base, xmldsig.Signatures(base)[0], c.Leaf.Raw, testcert.Now(), evidence)
	if e != nil || r.Level() != xades.LevelBB {
		t.Fatal(e)
	}

	evidence.Signer.CRLs = [][]byte{testcert.CRL(t, c, c.Leaf)}
	if r, e := v.ValidateEnveloped(context.Background(), d, xmldsig.Signatures(d)[0], c.Leaf.Raw, testcert.Now(), evidence); r != nil || !errors.Is(e, pki.ErrRevoked) {
		t.Fatal("revoked signer", e)
	}
}

func tsaPolicy() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 2, 3, 4, 1} }

type localTSA struct {
	chain testcert.Chain
	calls int
	bad   bool
}

func (t *localTSA) RoundTrip(ctx context.Context, query []byte) (io.ReadCloser, error) {
	t.calls++
	if t.bad {
		q, e := timestamp.CreateRequest(ctx, []byte("wrong imprint"), timestamp.RequestOptions{Policy: tsaPolicy()})
		if e != nil {
			return nil, e
		}

		query = q.DER()
	}

	r, e := timestamp.IssueResponse(ctx, query, t.chain.TSAKey, t.chain.TSA.Raw, timestamp.IssueOptions{Policy: tsaPolicy(), SerialNumber: big.NewInt(int64(t.calls)), GenTime: testcert.Now(), ExtraCertificates: [][]byte{t.chain.Root.Raw}})

	return io.NopCloser(bytes.NewReader(r)), e
}

func timeOptions(t testing.TB, c testcert.Chain) xades.TimedOptions {
	t.Helper()

	v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{c.Root.Raw}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{tsaPolicy()}})
	if e != nil {
		t.Fatal(e)
	}

	return xades.TimedOptions{TSA: v, At: testcert.Now(), Evidence: pki.Evidence{CRLs: [][]byte{testcert.CRL(t, c)}}}
}

func basicDocument(t *testing.T, c testcert.Chain) *document.Document {
	t.Helper()

	d, _, e := xades.SignBasicEnveloped(context.Background(), input(t), c.LeafKey, c.Leaf.Raw, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: testcert.Now().Add(-time.Second)})
	if e != nil {
		t.Fatal(e)
	}

	return d
}
