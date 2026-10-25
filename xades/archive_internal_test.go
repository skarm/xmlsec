package xades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestArchiveImprintWorkingStorage(t *testing.T) {
	ctx := t.Context()
	chain := testcert.New(t)

	payload, err := document.ParseReader(ctx, strings.NewReader(`<r ID="data" xmlns:unused="urn:archive-context">`+strings.Repeat("&amp;", 1<<20)+`</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	signed, _, err := SignBasicEnveloped(ctx, payload, chain.LeafKey, chain.Leaf.Raw, SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}

	clone, err := tree.Clone(ctx, signed)
	if err != nil {
		t.Fatal(err)
	}

	sig := xmldsig.Signatures(clone)[0]

	qp, err := qualifying(sig)
	if err != nil {
		t.Fatal(err)
	}

	_, root := tree.Unwrap(qp)
	unsigned := xnode("UnsignedProperties")
	properties := xnode("UnsignedSignatureProperties")
	add(unsigned, properties)
	add(root, unsigned)

	raw, err := clone.XML(ctx)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := document.Parse(ctx, raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	selected := xmldsig.Signatures(doc)[0]

	basic, err := verifyBasicEnveloped(ctx, doc, selected, chain.Leaf.Raw, VerifyOptions{}, true)
	if err != nil {
		t.Fatal(err)
	}

	usp, err := unsignedProperties(selected)
	if err != nil {
		t.Fatal(err)
	}

	allocated := ^uint64(0)

	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		imprint, err := archiveImprint(ctx, basic, usp, document.Element{}, c14n.Exclusive, 16<<20, crypto.SHA256)
		if err != nil || len(imprint.Digest) != 32 {
			t.Fatal(imprint, err)
		}

		runtime.ReadMemStats(&after)
		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}

	if allocated > 256<<10 {
		t.Fatalf("archive hashing allocated %d bytes for already retained 1 MiB payload", allocated)
	}

	if _, err := archiveImprint(ctx, basic, usp, document.Element{}, c14n.Exclusive, 1024, crypto.SHA256); !errors.Is(err, ErrProfile) {
		t.Fatal("archive limit", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := archiveImprint(canceled, basic, usp, document.Element{}, c14n.Exclusive, 16<<20, crypto.SHA256); !errors.Is(err, context.Canceled) {
		t.Fatal("archive cancellation", err)
	}
	// Neither digesting nor errors may alter the signed snapshot.
	current, err := doc.XML(ctx)
	if err != nil || !bytes.Equal(current, raw) {
		t.Fatal("archive hashing changed source", err)
	}
	for _, method := range []string{c14n.Canonical10, c14n.Canonical11} {
		t.Run("archive method applies to SignedInfo/"+method, func(t *testing.T) {
			var expected, wrong bytes.Buffer
			if err := archiveInputReferences(ctx, basic, &expected); err != nil {
				t.Fatal(err)
			}
			wrong.Write(expected.Bytes())
			for _, local := range []string{"SignedInfo", "SignatureValue", "KeyInfo"} {
				element, err := childNamed(selected, ds(local))
				if err != nil {
					t.Fatal(err)
				}
				var archiveBytes, signatureBytes bytes.Buffer
				if err := c14n.WriteElement(ctx, &archiveBytes, element, c14n.Options{Algorithm: method}); err != nil {
					t.Fatal(err)
				}
				expected.Write(archiveBytes.Bytes())
				if local == "SignedInfo" {
					if err := c14n.WriteElement(ctx, &signatureBytes, element, c14n.Options{Algorithm: c14n.Exclusive}); err != nil {
						t.Fatal(err)
					}
					if bytes.Equal(archiveBytes.Bytes(), signatureBytes.Bytes()) || !bytes.Contains(archiveBytes.Bytes(), []byte(`xmlns:unused="urn:archive-context"`)) {
						t.Fatal("canonicalization countercontrol has identical bytes")
					}
					wrong.Write(signatureBytes.Bytes())
				} else {
					wrong.Write(archiveBytes.Bytes())
				}
			}
			want, old := sha256.Sum256(expected.Bytes()), sha256.Sum256(wrong.Bytes())
			got, err := archiveImprint(ctx, basic, usp, document.Element{}, method, 16<<20, crypto.SHA256)
			if err != nil || !bytes.Equal(got.Digest, want[:]) || bytes.Equal(got.Digest, old[:]) {
				t.Fatal("archive SignedInfo used the signature method", err)
			}
		})
	}
}

func TestEmbeddedBase64WorkingStorage(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 1<<20)
	encoded := base64.StdEncoding.EncodeToString(payload)

	var source strings.Builder
	source.WriteString("<v>")

	for len(encoded) > 0 {
		n := min(len(encoded), 1024)
		source.WriteString(encoded[:n])
		source.WriteString(" \n\t<!--split-->")

		encoded = encoded[n:]
	}

	source.WriteString("</v>")

	doc, err := document.ParseReader(t.Context(), strings.NewReader(source.String()), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	measure := func(run func() error) uint64 {
		t.Helper()

		allocated := ^uint64(0)

		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			if err := run(); err != nil {
				t.Fatal(err)
			}

			runtime.ReadMemStats(&after)
			allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
		}

		return allocated
	}
	allocated := measure(func() error {
		result, err := decodeElementBase64(t.Context(), doc.Root(), source.Len(), len(payload))
		if err == nil && !bytes.Equal(result, payload) {
			return errors.New("decoded value changed")
		}

		return err
	})
	t.Logf("%d decoded bytes: %d allocated bytes", len(payload), allocated)

	if allocated > uint64(len(payload))+(64<<10) {
		t.Fatalf("Base64 decoding copied encoded XML text: %d allocated", allocated)
	}

	for _, limits := range [][2]int{{64, len(payload)}, {source.Len(), len(payload) - 1}} {
		allocated = measure(func() error {
			result, err := decodeElementBase64(t.Context(), doc.Root(), limits[0], limits[1])
			if result != nil || !errors.Is(err, ErrProfile) {
				return errors.New("base64 input escaped budget")
			}

			return nil
		})
		if allocated > 64<<10 {
			t.Fatalf("rejected Base64 allocated %d bytes", allocated)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if result, err := decodeElementBase64(ctx, doc.Root(), source.Len(), len(payload)); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(result, err)
	}

	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()

	counted := &decodeCancelContext{Context: ctx, cancel: cancel}
	if result, err := decodeElementBase64(counted, doc.Root(), source.Len(), len(payload)); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("decode did not observe cancellation during scan", err)
	}
}

func TestEmbeddedBase64ChunkBoundaries(t *testing.T) {
	for _, tc := range []struct {
		xml   string
		want  string
		valid bool
	}{
		{`<v>Y<!--split-->Q<![CDATA[=]]>=</v>`, "a", true},
		{"<v>\tY Q= =\r\n</v>", "a", true},
		{`<v/>`, "", true},
		{`<v>YR==</v>`, "", false},
		{`<v>YQ==<!--split-->YQ==</v>`, "", false},
		{`<v>YQ=</v>`, "", false},
		{"<v>YQ==\u00a0</v>", "", false},
	} {
		t.Run(tc.xml, func(t *testing.T) {
			doc, err := document.Parse(t.Context(), []byte(tc.xml), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}

			result, err := decodeElementBase64(t.Context(), doc.Root(), len(tc.xml), 16)
			if tc.valid && (err != nil || string(result) != tc.want) {
				t.Fatal(string(result), err)
			}

			if !tc.valid && (err == nil || result != nil) {
				t.Fatal("invalid base64 accepted", string(result), err)
			}
		})
	}
}

func TestTokenEncodingWorkingStorage(t *testing.T) {
	c := testcert.New(t)
	large := *c.Root
	large.SerialNumber = big.NewInt(100)

	padding, err := asn1.Marshal(bytes.Repeat([]byte{7}, 256<<10))
	if err != nil {
		t.Fatal(err)
	}

	large.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: padding}}

	extra, err := x509.CreateCertificate(rand.Reader, &large, &large, c.RootKey.Public(), c.RootKey)
	if err != nil {
		t.Fatal(err)
	}

	q, err := timestamp.CreateRequest(t.Context(), []byte("payload"), timestamp.RequestOptions{Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := timestamp.IssueResponse(t.Context(), q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: q.Policy(), SerialNumber: big.NewInt(1), GenTime: testcert.Now(), ExtraCertificates: [][]byte{extra}})
	if err != nil {
		t.Fatal(err)
	}

	response, err := timestamp.ParseResponse(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}

	token, err := timestamp.ParseToken(t.Context(), response.TokenDER())
	if err != nil {
		t.Fatal(err)
	}

	want := base64.StdEncoding.EncodeToString(token.DER())
	allocated := ^uint64(0)

	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		value, err := encodeBase64(t.Context(), token.Size(), token.WriterTo(t.Context()))

		runtime.ReadMemStats(&after)

		if err != nil || value != want {
			t.Fatal("encoded token changed", err)
		}

		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}

	t.Logf("%d encoded bytes: %d allocated bytes", len(want), allocated)

	if allocated > uint64(len(want))+(64<<10) {
		t.Fatalf("token encoding retained extra DER/Base64 copies: %d allocated", allocated)
	}

	allocated = ^uint64(0)

	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		n, err := timestamp.WriteResponse(t.Context(), io.Discard, q.DER(), c.TSAKey, c.TSA.Raw, timestamp.IssueOptions{Policy: q.Policy(), SerialNumber: big.NewInt(1), GenTime: testcert.Now(), ExtraCertificates: [][]byte{extra}})

		runtime.ReadMemStats(&after)

		if err != nil || n < int64(len(extra)) {
			t.Fatal("response writer", n, err)
		}

		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}

	t.Logf("response issuance with %d extra certificate bytes: %d allocated", len(extra), allocated)

	if allocated > uint64(len(extra))+(256<<10) {
		t.Fatalf("TSA response writer buffered full token/response: %d allocated", allocated)
	}
}

func FuzzEmbeddedBase64(f *testing.F) {
	for _, seed := range []string{"", "YQ==", "YR==", "YQ==YQ==", "\tY Q= =\n", "YQ="} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 {
			t.Skip()
		}

		var source bytes.Buffer
		source.WriteString("<v>")

		for offset := 0; offset < len(input); {
			end := min(offset+3, len(input))
			if err := xml.EscapeText(&source, []byte(input[offset:end])); err != nil {
				t.Fatal(err)
			}

			source.WriteString("<!--split-->")

			offset = end
		}

		source.WriteString("</v>")

		doc, err := document.Parse(t.Context(), source.Bytes(), document.DefaultLimits())
		if err != nil {
			t.Skip()
		}

		filtered := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}

			return r
		}, input)
		want, wantErr := base64.StdEncoding.Strict().DecodeString(filtered)

		got, err := decodeElementBase64(t.Context(), doc.Root(), source.Len(), 8192)
		if wantErr == nil && (err != nil || !bytes.Equal(got, want)) {
			t.Fatalf("base64 %q: %x %v, want %x", input, got, err, want)
		}

		if wantErr != nil && (err == nil || got != nil) {
			t.Fatalf("accepted invalid base64 %q", input)
		}
	})
}

func TestValidationMaterialWorkingStorage(t *testing.T) {
	c := testcert.New(t)

	padding, err := asn1.Marshal(bytes.Repeat([]byte{7}, 1<<20))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: testcert.Now(), NextUpdate: testcert.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: padding}}}, c.Root, c.RootKey)
	if err != nil {
		t.Fatal(err)
	}

	material := ValidationMaterial{CRLs: [][]byte{raw}}
	allocated := ^uint64(0)

	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		err := checkRawMaterial(t.Context(), material)
		evidence := material.evidence()

		runtime.ReadMemStats(&after)

		if err != nil || len(evidence.CRLs) != 1 || !bytes.Equal(evidence.CRLs[0], raw) {
			t.Fatal(err)
		}

		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}

	t.Logf("%d CRL bytes: %d allocated bytes", len(raw), allocated)

	if allocated > 64<<10 {
		t.Fatalf("validation material copied DER for indexing/evidence: %d allocated", allocated)
	}

	encoded := base64.StdEncoding.EncodeToString(raw)
	allocated = ^uint64(0)

	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		node, err := makeRevocationValues(t.Context(), material.evidence())

		runtime.ReadMemStats(&after)

		if err != nil {
			t.Fatal(err)
		}

		if got := node.Children[0].Children[0].Children[0].Data; got != encoded {
			t.Fatal("encoded CRL changed")
		}

		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
	}

	t.Logf("%d encoded CRL bytes: %d allocated bytes", len(encoded), allocated)

	if allocated > uint64(len(encoded))+(64<<10) {
		t.Fatalf("revocation encoding copied complete Base64: %d allocated", allocated)
	}

	if err := checkRawMaterial(t.Context(), ValidationMaterial{CRLs: [][]byte{raw, bytes.Clone(raw)}}); !errors.Is(err, ErrProfile) {
		t.Fatal("duplicate CRL accepted", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := checkRawMaterial(ctx, material); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()

	counted := &decodeCancelContext{Context: ctx, cancel: cancel}
	if node, err := makeRevocationValues(counted, material.evidence()); node != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("encoding did not observe cancellation between chunks", err)
	}
}

func TestUnsignedDraftWorkingStorageAndOwnership(t *testing.T) {
	chain := testcert.New(t)

	source, err := document.ParseReader(t.Context(), strings.NewReader(`<r ID="data">`+strings.Repeat(`<item>value</item>`, 8192)+`</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	signed, _, err := SignBasicEnveloped(t.Context(), source, chain.LeafKey, chain.Leaf.Raw, SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: testcert.Now()})
	if err != nil {
		t.Fatal(err)
	}

	for _, present := range []bool{false, true} {
		t.Run(strconv.FormatBool(present), func(t *testing.T) {
			selected := xmldsig.Signatures(signed)[0]

			before, err := signed.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			allocated := ^uint64(0)

			var (
				draft    *document.Document
				unsigned *tree.Node
			)

			for range 3 {
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)

				draft, unsigned, err = unsignedDraft(t.Context(), signed, selected)

				runtime.ReadMemStats(&after)

				if err != nil {
					t.Fatal(err)
				}

				allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
			}

			t.Logf("unsigned edit working storage: %d bytes", allocated)
			// Copying the edited ancestor's child list retains sibling order;
			// every unedited sibling subtree must remain borrowed.
			if allocated > uint64(len(tree.Root(signed).Children))*8+(32<<10) {
				t.Fatalf("unsigned edit cloned signed payload: %d bytes", allocated)
			}

			add(unsigned, &tree.Node{Kind: tree.CommentNode, Data: "owned edit"})

			published, err := publishDraft(t.Context(), draft)
			if err != nil {
				t.Fatal(err)
			}

			after, err := signed.XML(t.Context())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("editing/publishing draft changed the source", err)
			}

			selected = xmldsig.Signatures(published)[0]
			if _, err := verifyBasicEnveloped(t.Context(), published, selected, chain.Leaf.Raw, VerifyOptions{}, true); err != nil {
				t.Fatal("draft publication changed authenticated content", err)
			}

			signed = published
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, _, err := unsignedDraft(ctx, signed, xmldsig.Signatures(signed)[0]); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type decodeCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *decodeCancelContext) Err() error {
	c.checks++
	if c.checks == 3 {
		c.cancel()
	}

	return c.Context.Err()
}

func TestValidationMaterialCertificateEncodings(t *testing.T) {
	chain := testcert.New(t)
	for _, test := range testcert.CertificateEncodings(t, chain) {
		t.Run(test.Name, func(t *testing.T) {
			err := checkRawMaterial(t.Context(), ValidationMaterial{Certificates: [][]byte{test.DER}})
			if test.Valid {
				if err != nil {
					t.Fatal("valid embedded certificate rejected", err)
				}
			} else if !errors.Is(err, ErrProfile) {
				t.Fatal("invalid embedded certificate accepted", err)
			}
		})
	}
	large := *chain.Leaf
	large.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: bytes.Repeat([]byte{0x42}, 2<<20)}}
	raw, err := x509.CreateCertificate(rand.Reader, &large, chain.Root, chain.LeafKey.Public(), chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 1<<20 {
		t.Fatal("fixture did not exceed a default certificate cap")
	}
	if err := checkRawMaterial(t.Context(), ValidationMaterial{Certificates: [][]byte{raw}}); err != nil {
		t.Fatal("new decoder narrowed the existing4MiB material cap", err)
	}
}

func TestValidationMaterialCRLVersions(t *testing.T) {
	chain := testcert.New(t)
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			raw := testcert.CRL(t, chain)
			if version == "v1" {
				raw = testcert.CRLV1(t, chain)
			}
			material := ValidationMaterial{CRLs: [][]byte{raw}}
			if err := checkRawMaterial(t.Context(), material); err != nil {
				t.Fatal("valid CRL material rejected", err)
			}
			node, err := makeRevocationValues(t.Context(), material.evidence())
			if err != nil {
				t.Fatal(err)
			}
			if got := node.Children[0].Children[0].Children[0].Data; got != base64.StdEncoding.EncodeToString(raw) {
				t.Fatal("embedded CRL no longer has its original DER")
			}
			if err := checkRawMaterial(t.Context(), ValidationMaterial{CRLs: [][]byte{append(bytes.Clone(raw), 0)}}); !errors.Is(err, ErrProfile) {
				t.Fatal("trailing CRL data accepted", err)
			}
		})
	}
	large, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: testcert.Now(), NextUpdate: testcert.Now().Add(time.Hour), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: bytes.Repeat([]byte{42}, 2<<20)}}}, chain.Root, chain.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRawMaterial(t.Context(), ValidationMaterial{CRLs: [][]byte{large}}); err != nil {
		t.Fatal("existing4MiB CRL material cap narrowed", err)
	}
	if err := checkRawMaterial(t.Context(), ValidationMaterial{CRLs: [][]byte{make([]byte, (4<<20)+1)}}); !errors.Is(err, ErrProfile) {
		t.Fatal("material byte cap weakened", err)
	}
}
