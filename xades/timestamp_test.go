package xades_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/reference"
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
			s := bytes.ReplaceAll(b, []byte(tc.from), []byte(tc.to))
			if bytes.Equal(s, b) {
				t.Fatal("fixture replacement missing")
			}

			p, e := document.Parse(t.Context(), s, document.DefaultLimits())
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

func TestBaselineDataTimestampInputs(t *testing.T) {
	chain := testcert.New(t)
	tsa := timeOptions(t, chain)
	server := &localTSA{chain: chain}
	for _, method := range []string{c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments, c14n.Exclusive, c14n.ExclusiveWithComments} {
		for _, individual := range []bool{false, true} {
			t.Run(method+"/"+strconv.FormatBool(individual), func(t *testing.T) {
				source := baselineDocument(t, `<Envelope xmlns:u="urn:unused"><One ID="one">A</One><Two ID="two">B</Two><Slot/></Envelope>`)
				options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{ID: "first-data", URI: "#one"}, {ID: "second-data", URI: "#two"}}}, Properties: xades.BaselineProperties{SigningTime: testcert.Now().Add(time.Second)}}
				_, base, err := xades.SignBaseline(t.Context(), source, source.Root().Children()[2], chain.LeafKey, chain.Leaf.Raw, options)
				if err != nil {
					t.Fatal(err)
				}
				indexes := []int{0, 1}
				identifiers := []string(nil)
				if individual {
					indexes = []int{1, 0, 1}
					identifiers = []string{"#second-data", "#first-data", "#second-data"}
				}
				var input bytes.Buffer
				for _, index := range indexes {
					if _, err := base.Basic().Signature().References()[index].WriteCanonicalizedInput(t.Context(), &input, reference.Transform{Algorithm: method}); err != nil {
						t.Fatal(err)
					}
				}
				request, err := timestamp.CreateRequest(t.Context(), input.Bytes(), timestamp.RequestOptions{Policy: tsaPolicy()})
				if err != nil {
					t.Fatal(err)
				}
				token, err := tsa.TSA.Fetch(t.Context(), server, request, tsa.At, tsa.Evidence)
				if err != nil {
					t.Fatal(err)
				}
				options.Properties.DataTimestamps = []xades.DataTimestampProperty{{Individual: individual, ObjectReferences: identifiers, Canonicalization: reference.Transform{Algorithm: method}, TokenDER: token.TokenDER()}}
				_, verified, err := xades.SignBaseline(t.Context(), source, source.Root().Children()[2], chain.LeafKey, chain.Leaf.Raw, options)
				if err != nil {
					t.Fatal(err)
				}
				stamps := verified.DataTimestamps()
				if len(stamps) != 1 || stamps[0].CanonicalizationMethod() != method {
					t.Fatal("timestamp missing")
				}
				var actual bytes.Buffer
				if _, err := stamps[0].WriteImprintInput(t.Context(), &actual); err != nil || !bytes.Equal(actual.Bytes(), input.Bytes()) {
					t.Fatal("wrong ordered content input", actual.String(), input.String(), err)
				}
				imprint, err := timestamp.ImprintFor(t.Context(), actual.Bytes(), 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tsa.TSA.Verify(t.Context(), stamps[0].Token(), timestamp.Expectation{Imprint: imprint}, tsa.At, tsa.Evidence); err != nil {
					t.Fatal("independent TSA trust/binding stage", err)
				}
				stamps[0].TokenDER()[0] ^= 1
				stamps[0].ObjectReferences()[0] = "changed"
				if verified.DataTimestamps()[0].ObjectReferences()[0] == "changed" {
					t.Fatal("mutable result")
				}
				cancelled, cancel := context.WithCancel(t.Context())
				cancel()
				if _, err := stamps[0].WriteImprintInput(cancelled, io.Discard); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestBaselineIndividualTimestampManifest(t *testing.T) {
	chain := testcert.New(t)
	tsa := timeOptions(t, chain)
	source := baselineDocument(t, `<r><payload ID="payload">signed-data</payload></r>`)
	options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{ID: "manifest-ref", URI: "#manifest", Type: xmldsig.ManifestType}}, Objects: []xmldsig.ObjectTemplate{{Manifest: &xmldsig.ManifestTemplate{ID: "manifest", References: []xmldsig.ReferenceTemplate{{ID: "nested-data", URI: "#payload"}}}}}}, Properties: xades.BaselineProperties{SigningTime: testcert.Now().Add(time.Second)}, Validation: xades.BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive}}}}
	_, base, err := xades.SignBaseline(t.Context(), source, source.Root(), chain.LeafKey, chain.Leaf.Raw, options)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	if _, err := base.Basic().Signature().Manifests()[0].References()[0].WriteCanonicalizedInput(t.Context(), &input, reference.Transform{Algorithm: c14n.Exclusive}); err != nil {
		t.Fatal(err)
	}
	request, err := timestamp.CreateRequest(t.Context(), input.Bytes(), timestamp.RequestOptions{Policy: tsaPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	token, err := tsa.TSA.Fetch(t.Context(), &localTSA{chain: chain}, request, tsa.At, tsa.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	options.Properties.DataTimestamps = []xades.DataTimestampProperty{{Individual: true, ObjectReferences: []string{"#nested-data"}, Canonicalization: reference.Transform{Algorithm: c14n.Exclusive}, TokenDER: token.TokenDER()}}
	signed, verified, err := xades.SignBaseline(t.Context(), source, source.Root(), chain.LeafKey, chain.Leaf.Raw, options)
	if err != nil {
		t.Fatal(err)
	}
	var actual bytes.Buffer
	if _, err := verified.DataTimestamps()[0].WriteImprintInput(t.Context(), &actual); err != nil || !bytes.Equal(actual.Bytes(), input.Bytes()) {
		t.Fatal(actual.String(), err)
	}
	// Merely digesting a Manifest does not authenticate its child References.
	withoutRecursion := options.Validation
	withoutRecursion.Signature.Manifests = xmldsig.ManifestPolicy{}
	if result, err := xades.VerifyBaseline(t.Context(), signed, verified.Basic().Signature().Signature(), chain.Leaf.Raw, withoutRecursion); err == nil || result != nil {
		t.Fatal("unvalidated Manifest child accepted")
	}
	for _, identifier := range []string{"#signed-properties", "#payload", "#missing"} {
		options.Properties.DataTimestamps[0].ObjectReferences = []string{identifier}
		doc, result, err := xades.SignBaseline(t.Context(), source, source.Root(), chain.LeafKey, chain.Leaf.Raw, options)
		if err == nil || doc != nil || result != nil {
			t.Fatal("wrong content timestamp Reference accepted", identifier)
		}
	}
}

func TestHistoricalSignedContentTimestampRequired(t *testing.T) {
	chain := testcert.New(t)
	tsa := timeOptions(t, chain)
	zero := time.Duration(0)
	at := testcert.Now().Add(2 * time.Second)
	for _, certificatePayload := range []bool{false, true} {
		for _, correct := range []bool{true, false} {
			t.Run(strconv.FormatBool(certificatePayload)+"/"+strconv.FormatBool(correct), func(t *testing.T) {
				source := input(t)
				parent := source.Root()
				options := xades.BaselineSignOptions{Template: xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#invoice-1", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}}, Properties: xades.BaselineProperties{SigningTime: testcert.Now().Add(time.Second)}}
				if certificatePayload {
					source = nil
					parent = document.Element{}
					options.Template.References = []xmldsig.ReferenceTemplate{{URI: "urn:signer-certificate"}}
					options.Validation.Signature.External = &xmldsig.ExternalReferences{AllowedURIs: []string{"urn:signer-certificate"}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
						return io.NopCloser(bytes.NewReader(chain.Leaf.Raw)), nil
					})}
				}
				_, base, err := xades.SignBaseline(t.Context(), source, parent, chain.LeafKey, chain.Leaf.Raw, options)
				if err != nil {
					t.Fatal(err)
				}
				var content bytes.Buffer
				if _, err := base.Basic().Signature().References()[0].WriteCanonicalizedInput(t.Context(), &content, reference.Transform{Algorithm: c14n.Canonical10}); err != nil {
					t.Fatal(err)
				}
				data := content.Bytes()
				if !correct {
					data = []byte("wrong content imprint")
				}
				request, err := timestamp.CreateRequest(t.Context(), data, timestamp.RequestOptions{Policy: tsaPolicy()})
				if err != nil {
					t.Fatal(err)
				}
				token, err := tsa.TSA.Fetch(t.Context(), &localTSA{chain: chain}, request, tsa.At, tsa.Evidence)
				if err != nil {
					t.Fatal(err)
				}
				options.Properties.DataTimestamps = []xades.DataTimestampProperty{{TokenDER: token.TokenDER()}}
				signed, result, err := xades.SignBaseline(t.Context(), source, parent, chain.LeafKey, chain.Leaf.Raw, options)
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := xades.NewHistoricalValidator(xades.HistoricalConfig{SignerPKI: pki.HistoricalConfig{PKI: pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}}, TSA: tsa.TSA, MissingTSAAccuracy: &zero, RequireAllTimestamps: true, Baseline: options.Validation})
				if err != nil {
					t.Fatal(err)
				}
				evidence := xades.ValidationEvidence{Signer: tsa.Evidence, TSA: tsa.Evidence}
				trusted, report, err := verifier.Validate(t.Context(), signed, result.Basic().Signature().Signature(), chain.Leaf.Raw, at, evidence)
				if correct {
					if err != nil || trusted == nil || report.Indication() != xades.Passed || len(report.Timestamps()) != 1 || !report.Timestamps()[0].Content || !report.BestSignatureTime().Equal(at) {
						t.Fatalf("content timestamp current proof: %v %s %v %+v", report.Indication(), report.SubIndication(), err, report.Timestamps())
					}
					signatureHash := sha256.Sum256(mustSignatureValue(t, signed))
					tokenHash := sha256.Sum256(token.TokenDER())
					for _, proof := range report.Proofs() {
						if proof.ObjectSHA256 == hex.EncodeToString(signatureHash[:]) && proof.SourceSHA256 == hex.EncodeToString(tokenHash[:]) {
							t.Fatal("content timestamp minted SignatureValue PoE")
						}
					}
				} else if err == nil || trusted != nil || report.SubIndication() != "HASH_FAILURE" {
					t.Fatalf("required signed content timestamp ignored: %v %s %v", report.Indication(), report.SubIndication(), err)
				}
			})
		}
	}
}
