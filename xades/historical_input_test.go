package xades //nolint:testpackage // Exercises exact-byte evidence admission before the historical workflow.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/historical"
	"github.com/skarm/xmlsec/internal/historicalproof"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestHistoricalArchivesShareCertificateReference(t *testing.T) {
	t.Parallel()

	ctx, now := t.Context(), testcert.Now()
	chain := testcert.New(t)
	payload, err := document.Parse(ctx, []byte(`<r ID="document"><value>`+strings.Repeat("a", 8<<10)+`</value></r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	doc, signed, err := SignBasicEnveloped(ctx, payload, chain.LeafKey, chain.Leaf.Raw, SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: now})
	if err != nil {
		t.Fatal(err)
	}
	policy := asn1.ObjectIdentifier{1, 2, 3, 4}
	pkiConfig := pki.Config{Roots: [][]byte{chain.Root.Raw}, Revocation: pki.RequireCRL}
	proof := pki.Evidence{CRLs: [][]byte{testcert.CRL(t, chain)}}
	tsa, err := timestamp.NewVerifier(timestamp.Config{PKI: pkiConfig, AllowedPolicies: []asn1.ObjectIdentifier{policy}})
	if err != nil {
		t.Fatal(err)
	}
	transport := func(serial int64, at time.Time) timestamp.TransportFunc {
		return func(ctx context.Context, request []byte) (io.ReadCloser, error) {
			response, err := timestamp.IssueResponse(ctx, request, chain.TSAKey, chain.TSA.Raw, timestamp.IssueOptions{Policy: policy, SerialNumber: big.NewInt(serial), GenTime: at})
			return io.NopCloser(bytes.NewReader(response)), err
		}
	}
	doc, _, err = AddSignatureTimestamp(ctx, doc, signed.Signature().Signature(), chain.Leaf.Raw, transport(1, now), AddTimestampOptions{Validation: TimedOptions{TSA: tsa, At: now, Evidence: proof}})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewValidator(ValidatorConfig{SignerPKI: pkiConfig, TSA: tsa, MinimumLevel: LevelLT})
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err = verifier.EmbedValidationMaterial(ctx, doc, xmldsig.Signatures(doc)[0], chain.Leaf.Raw, now, ValidationEvidence{Signer: proof, TSA: proof})
	if err != nil {
		t.Fatal(err)
	}
	for renewal := range 2 {
		at := now.Add(time.Duration(renewal+1) * time.Second)
		doc, _, err = verifier.AddArchiveTimestamp(ctx, doc, xmldsig.Signatures(doc)[0], chain.Leaf.Raw, at, transport(int64(renewal+2), at), AddArchiveOptions{Canonicalization: c14n.Exclusive})
		if err != nil {
			t.Fatal(err)
		}
	}

	options := BaselineVerifyOptions{Signature: xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "ID"}}}
	baseline, err := VerifyBaseline(ctx, doc, xmldsig.Signatures(doc)[0], chain.Leaf.Raw, options)
	if err != nil {
		t.Fatal(err)
	}
	model, _, err := historicalInput(ctx, baseline, options, historical.Config{MaxBytes: 1 << 20, MaxObjects: 64, MaxTimestamps: 3}, ValidationEvidence{})
	if err != nil || len(model.Timestamps) != 3 || !model.Timestamps[1].Archive || !model.Timestamps[2].Archive {
		t.Fatalf("historicalInput: timestamps=%d, err=%v; want one signature timestamp and two archives", len(model.Timestamps), err)
	}
	digest := sha256.Sum256(chain.Leaf.Raw)
	count := 0
	for _, object := range model.Objects {
		for _, ref := range object.Refs {
			if ref.Hash != crypto.SHA256 || ref.Target != digest || !bytes.Equal(ref.Digest, digest[:]) {
				t.Fatalf("incorrect certificate reference: %+v", ref)
			}
			count++
		}
		if len(object.Refs) != 0 {
			key := sha256.Sum256(object.Bytes)
			if !slices.Contains(model.Timestamps[1].Covered, key) || !slices.Contains(model.Timestamps[2].Covered, key) {
				t.Fatal("both archives should cover the same signed properties")
			}
		}
	}
	if count != 1 {
		t.Fatalf("repeated archive changed distinct certificate reference count: got %d, want 1", count)
	}
	t.Run("aggregate bytes", func(t *testing.T) {
		t.Parallel()

		var total int
		for _, object := range model.Objects {
			total += len(object.Bytes)
		}
		for _, test := range []struct {
			name string
			max  int
			want error
		}{
			{"exact", total, nil},
			{"one byte short", total - 1, historical.ErrLimit},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				got, _, err := historicalInput(t.Context(), baseline, options, historical.Config{MaxBytes: test.max, MaxObjects: 64, MaxTimestamps: 3}, ValidationEvidence{})
				if !errors.Is(err, test.want) {
					t.Fatalf("historicalInput with limit %d, graph bytes %d: %v, want %v", test.max, total, err, test.want)
				}
				if test.want != nil {
					return
				}
				if !reflect.DeepEqual(got.Objects, model.Objects) {
					t.Fatalf("exact byte limit changed objects: got %d, want %d", len(got.Objects), len(model.Objects))
				}
				if len(got.Timestamps) != len(model.Timestamps) {
					t.Fatalf("exact byte limit retained %d timestamps, want %d", len(got.Timestamps), len(model.Timestamps))
				}
				for i, stamp := range got.Timestamps {
					want := model.Timestamps[i]
					if stamp.Archive != want.Archive || stamp.Imprint.Hash != want.Imprint.Hash || !bytes.Equal(stamp.Imprint.Digest, want.Imprint.Digest) || !slices.Equal(stamp.Covered, want.Covered) {
						t.Errorf("exact byte limit changed timestamp %d imprint or coverage", i)
					}
				}
			})
		}
	})
}

func TestHistoricalObjectsMergeExactEvidence(t *testing.T) {
	t.Parallel()

	raw := []byte("exact object bytes")
	first := sha256.Sum256([]byte("first child"))
	second := sha256.Sum256([]byte("second child"))
	objects := historicalObjects{ctx: t.Context(), maximum: 1, remaining: len(raw), index: make(map[[sha256.Size]byte]int)}
	children := [][sha256.Size]byte{first}
	key, err := objects.add(raw, historicalproof.Data, children)
	if err != nil || key != sha256.Sum256(raw) {
		t.Fatalf("add data = (%x, %v), want digest of the exact bytes", key, err)
	}
	children[0] = second
	if got, err := objects.add(raw, historicalproof.Signature, [][sha256.Size]byte{first, second}); err != nil || got != key {
		t.Fatalf("add same bytes as signature = (%x, %v), want (%x, nil)", got, err, key)
	}
	if _, err := objects.add(raw, historicalproof.Certificate, nil); !errors.Is(err, historical.ErrInput) {
		t.Errorf("add same bytes as incompatible kind = %v, want %v", err, historical.ErrInput)
	}
	if _, err := objects.add([]byte("unrelated"), historicalproof.Data, nil); !errors.Is(err, historical.ErrLimit) {
		t.Errorf("add second object beyond budget = %v, want %v", err, historical.ErrLimit)
	}
	if len(objects.objects) != 1 || len(objects.index) != 1 || objects.remaining != 0 {
		t.Fatalf("admission after merge and refusal = %d objects, %d indexed, %d bytes left, want 1, 1, 0", len(objects.objects), len(objects.index), objects.remaining)
	}
	got := objects.objects[0]
	if got.Kind != historicalproof.Signature || !bytes.Equal(got.Bytes, raw) || !slices.Equal(got.Contains, [][sha256.Size]byte{first, second}) {
		t.Errorf("admitted object = %+v, want original signature bytes and both children once", got)
	}
}

func TestHistoricalObjectsRecognizeEmbeddedRevocationList(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	crl := testcert.CRL(t, chain)
	const start = `<Values xmlns:xades="` + Namespace + `">`
	const end = `</Values>`
	element := func(value []byte) string {
		return "<xades:EncapsulatedCRLValue>" + base64.StdEncoding.EncodeToString(value) + "</xades:EncapsulatedCRLValue>"
	}
	source := start + element(crl) + element([]byte("ordinary text in a lookalike element")) + end
	objects := historicalObjects{ctx: t.Context(), maximum: 2, remaining: 2 * len(source), index: make(map[[sha256.Size]byte]int)}
	ids, err := objects.contained([]byte(source))
	wantID := sha256.Sum256(crl)
	if err != nil || !slices.Equal(ids, [][sha256.Size]byte{wantID}) || len(objects.objects) != 1 {
		t.Fatalf("contained = (%x, %v), %d objects, want one CRL with ID %x", ids, err, len(objects.objects), wantID)
	}
	got := objects.objects[0]
	if got.Kind != historicalproof.CRL || !bytes.Equal(got.Bytes, crl) || len(got.Contains) != 0 {
		t.Errorf("admitted CRL has kind %s, exact bytes = %t, children = %x", got.Kind, bytes.Equal(got.Bytes, crl), got.Contains)
	}
}

func TestHistoricalObjectsRetainOCSPCertificateRelationship(t *testing.T) {
	t.Parallel()

	chain := testcert.New(t)
	request, err := pki.CreateOCSPRequest(chain.Leaf.Raw, chain.Root.Raw, crypto.SHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	at := testcert.Now()
	response, err := pki.CreateOCSPResponse(t.Context(), request, chain.Leaf.Raw, chain.Root.Raw, chain.Responder.Raw, chain.ResponderKey, pki.OCSPResponseTemplate{
		Status: pki.OCSPGood, ProducedAt: at, ThisUpdate: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := `<EncapsulatedOCSPValue xmlns="` + Namespace + `">` + base64.StdEncoding.EncodeToString(response) + "</EncapsulatedOCSPValue>"
	objects := historicalObjects{
		ctx: t.Context(), maximum: 2, remaining: len(response) + len(chain.Responder.Raw),
		index: make(map[[sha256.Size]byte]int),
	}
	ids, err := objects.contained([]byte(raw))
	want := sha256.Sum256(response)
	if err != nil || !slices.Equal(ids, [][sha256.Size]byte{want}) || len(objects.objects) != 2 {
		t.Fatalf("contained = (%x, %v), %d objects, want OCSP ID %x and two objects", ids, err, len(objects.objects), want)
	}
	certID := sha256.Sum256(chain.Responder.Raw)
	cert := objects.objects[objects.index[certID]]
	ocsp := objects.objects[objects.index[want]]
	if cert.Kind != historicalproof.Certificate || !bytes.Equal(cert.Bytes, chain.Responder.Raw) || len(cert.Contains) != 0 {
		t.Error("embedded responder certificate was not retained as a distinct leaf object")
	}
	if ocsp.Kind != historicalproof.OCSP || !bytes.Equal(ocsp.Bytes, response) || !slices.Equal(ocsp.Contains, [][sha256.Size]byte{certID}) {
		t.Error("OCSP response did not retain exact bytes and a link to the responder certificate")
	}
}

func TestHistoricalSignedInfoOptionsRetainsCanonicalizationParameters(t *testing.T) {
	t.Parallel()

	const start = `<ds:SignedInfo xmlns:ds="` + xmldsig.Namespace + `" xmlns:ec="` + c14n.Exclusive + `">`
	const method = `<ds:CanonicalizationMethod Algorithm="` + c14n.Exclusive + `">`
	for _, tc := range []struct {
		name, children string
		want           []string
		wantErr        error
	}{
		{"inclusive_prefix_list", method + `<ec:InclusiveNamespaces PrefixList="p&#x9;#default  q"/></ds:CanonicalizationMethod>`, []string{"p", "#default", "q"}, nil},
		{"missing_method", "", nil, ErrProfile},
		{"unexpected_parameter", method + "<ec:Other/></ds:CanonicalizationMethod>", nil, ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := document.Parse(t.Context(), []byte(start+tc.children+"</ds:SignedInfo>"), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			opts, err := historicalSignedInfoOptions(doc.Root(), 512)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("historicalSignedInfoOptions = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && (opts.Algorithm != c14n.Exclusive || opts.MaxOutputBytes != 512 || !slices.Equal(opts.InclusivePrefixes, tc.want)) {
				t.Errorf("historicalSignedInfoOptions = %+v, want exclusive algorithm, 512-byte limit and prefixes %v", opts, tc.want)
			}
		})
	}
}

func TestHistoricalObjectsDistinguishSparseXMLFromCancellation(t *testing.T) {
	t.Parallel()

	const sparse = "<first/><second/>"
	objects := historicalObjects{ctx: t.Context()}
	if ids, err := objects.contained([]byte(sparse)); ids != nil || err != nil {
		t.Errorf("sparse XML produced containment IDs %x, error %v", ids, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	objects.ctx = ctx
	if ids, err := objects.contained([]byte("<first/>")); ids != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled containment = (%x, %v), want no IDs and cancellation", ids, err)
	}
}

func TestHistoricalObjectsLinkOnlyReproducedCanonicalEncoding(t *testing.T) {
	t.Parallel()

	const protected = `<r z="2" a="1"/>`
	for _, tc := range []struct {
		name, target string
		wantLink     bool
	}{
		{"exact_reencoding", `<r a="1" z="2"></r>`, true},
		{"different_attribute", `<r a="1" z="3"></r>`, false},
		{"too_short_to_hold_result", `<r></r>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			objects := historicalObjects{ctx: t.Context(), maximum: 2, remaining: len(protected) + len(tc.target), index: make(map[[sha256.Size]byte]int)}
			parent, err := objects.add([]byte(protected), historicalproof.Data, nil)
			if err != nil {
				t.Fatal(err)
			}
			original, err := objects.add([]byte(tc.target), historicalproof.Data, nil)
			if err != nil {
				t.Fatal(err)
			}
			opts := c14n.Options{Algorithm: c14n.Canonical10}
			for range 2 {
				if err := objects.linkCanonicalEncoding(parent, original, opts); err != nil {
					t.Fatalf("linkCanonicalEncoding: %v", err)
				}
			}
			var want [][sha256.Size]byte
			if tc.wantLink {
				want = append(want, original)
			}
			if got := objects.objects[0].Contains; !slices.Equal(got, want) {
				t.Errorf("canonical links = %x, want %x", got, want)
			}
		})
	}
}

func TestParseHistoricalTimeStampTokenShapeAndLimits(t *testing.T) {
	t.Parallel()

	const one = `<x:EncapsulatedTimeStamp>AQI=</x:EncapsulatedTimeStamp>`
	const two = `<x:EncapsulatedTimeStamp>AwQ=</x:EncapsulatedTimeStamp>`
	const explicit = `<ds:CanonicalizationMethod Algorithm="` + c14n.Exclusive + `"/>`
	for _, tc := range []struct {
		name, element, attrs, content string
		maxBytes                      int
		wantMethod                    string
		wantTokens                    [][]byte
		wantErr                       error
	}{
		{"signature_defaults_to_canonical10", "x:SignatureTimeStamp", "", one, 2, c14n.Canonical10, [][]byte{{1, 2}}, nil},
		{"archive_retains_token_order", "a:ArchiveTimeStamp", "", explicit + one + two, 2, c14n.Exclusive, [][]byte{{1, 2}, {3, 4}}, nil},
		{"archive_token_count_exceeded", "a:ArchiveTimeStamp", "", strings.Repeat(one, 33), 2, "", nil, ErrTimestamp},
		{"signature_has_two_tokens", "x:SignatureTimeStamp", "", one + two, 2, "", nil, ErrProfile},
		{"token_too_large", "x:SignatureTimeStamp", "", one, 1, "", nil, ErrTimestamp},
		{"invalid_timestamp_attribute", "x:SignatureTimeStamp", ` unexpected="yes"`, one, 2, "", nil, ErrProfile},
		{"text_outside_token", "x:SignatureTimeStamp", "", "text" + one, 2, "", nil, ErrProfile},
		{"nonempty_canonicalization_method", "x:SignatureTimeStamp", "", `<ds:CanonicalizationMethod Algorithm="` + c14n.Exclusive + `"><r/></ds:CanonicalizationMethod>` + one, 2, "", nil, ErrTimestamp},
		{"unexpected_child", "x:SignatureTimeStamp", "", "<Other/>", 2, "", nil, ErrTimestamp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source := "<" + tc.element + ` xmlns:x="` + Namespace + `" xmlns:a="` + Namespace141 + `" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"` + tc.attrs + ">" + tc.content + "</" + tc.element + ">"
			doc, err := document.Parse(t.Context(), []byte(source), document.DefaultLimits())
			if err != nil {
				t.Fatalf("parse XML fixture: %v", err)
			}
			method, tokens, err := parseHistoricalTimeStamp(t.Context(), doc.Root(), tc.maxBytes)
			if method != tc.wantMethod || !slices.EqualFunc(tokens, tc.wantTokens, bytes.Equal) || !errors.Is(err, tc.wantErr) {
				t.Errorf("parseHistoricalTimeStamp = (%q, %x, %v), want (%q, %x, %v)", method, tokens, err, tc.wantMethod, tc.wantTokens, tc.wantErr)
			}
		})
	}
}
