package consumer_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

var _ xmldsig.ContextSigner = (*signingProvider)(nil)

func TestExternalDigestReplayDetectsChangedResource(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := "original"
	opened, closed := 0, 0
	resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		opened++
		return &trackedInput{Reader: strings.NewReader(value), close: func() error { closed++; return nil }}, nil
	})
	signed, err := xmldsig.SignDetached(t.Context(), []xmldsig.DetachedReference{{URI: "urn:record"}}, key, resolver, xmldsig.DetachedSignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := xmldsig.VerifyDetached(t.Context(), signed, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{"urn:record"}})
	if err != nil {
		t.Fatal(err)
	}
	ref := verified.References()[0]
	if ref.Size() != len(value) || !bytes.Equal(ref.Digest(), sha256Sum(value)) {
		t.Fatal(ref.Size(), ref.Digest())
	}
	value = "modified"
	var output bytes.Buffer
	n, err := ref.WriteDigestInput(t.Context(), &output)
	if !errors.Is(err, xmldsig.ErrDigest) || n != int64(output.Len()) || opened != closed {
		t.Fatal(n, err, opened, closed)
	}
}

func sha256Sum(value string) []byte { hash := sha256.Sum256([]byte(value)); return hash[:] }

func TestShortHMACWorkingStorage(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	message := []byte("a small authenticated message")
	expected := hmac.New(sha256.New, key)
	_, _ = expected.Write(message)
	policy := xmldsig.HMACPolicy()
	allocation := allocatedDuring(t, func() error {
		got, err := xmldsig.ComputeHMAC(t.Context(), message, key, xmldsig.HMACSHA256, 0, policy)
		if err == nil && !hmac.Equal(got, expected.Sum(nil)) {
			return errors.New("HMAC differs from standard library")
		}
		return err
	})
	t.Logf("short HMAC: %d allocated bytes", allocation)
	if allocation > 8<<10 {
		t.Fatal("short HMAC allocated a full stream buffer", allocation)
	}
}

func TestReferenceWritesDirectlyToHash(t *testing.T) {
	doc, err := document.ParseReader(t.Context(), strings.NewReader(`<r a="2">value&amp;text</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	set, err := doc.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	data, err := reference.Nodes(set)
	if err != nil {
		t.Fatal(err)
	}
	transforms := []reference.Transform{{Algorithm: c14n.Exclusive}}
	hash := sha256.New()
	report, err := reference.Write(t.Context(), hash, data, transforms, reference.Options{})
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(`<r a="2">value&amp;text</r>`))
	if !bytes.Equal(hash.Sum(nil), expected[:]) || report.Size() != len(`<r a="2">value&amp;text</r>`) {
		t.Fatal(report, hash.Sum(nil))
	}
	failure := errors.New("sink failed")
	if report, err := reference.Write(t.Context(), &prefixFailure{remaining: 3, failure: failure}, data, transforms, reference.Options{}); report != nil || !errors.Is(err, failure) {
		t.Fatal(report, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reference.Write(ctx, io.Discard, data, transforms, reference.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReferenceReaderWritesBeforeEOF(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		var output bytes.Buffer
		first, rest := "one", "two"
		var transforms []reference.Transform
		if encoded {
			first, rest = "b25l", "dHdv"
			transforms = []reference.Transform{{Algorithm: reference.Base64}}
		}
		reader := &gatedInput{first: strings.NewReader(first), rest: strings.NewReader(rest), ready: func() bool { return output.Len() > 0 }}
		report, err := reference.WriteReader(t.Context(), &output, reader, transforms, reference.Options{})
		if err != nil || reader.early || output.String() != "onetwo" || report.Size() != 6 {
			t.Fatal(report, err, output.String(), reader.early)
		}
	}
	read := false
	source := readFunc(func([]byte) (int, error) { read = true; return 0, io.EOF })
	if _, err := reference.WriteReader(t.Context(), io.Discard, source, []reference.Transform{{Algorithm: "urn:unapproved"}}, reference.Options{}); err == nil || read {
		t.Fatal(err, read)
	}
}

func TestSigningProviderContextAcrossPackages(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: at, NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificate, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"XMLDSig", "CMS"} {
		t.Run(name, func(t *testing.T) {
			provider := &signingProvider{key: key}
			adapter, err := xmldsig.AdaptContextSigner(provider)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.WithValue(t.Context(), providerContextKey{}, provider))
			defer cancel()

			sign := func() ([]byte, error) {
				if name == "XMLDSig" {
					return xmldsig.SignMessage(ctx, []byte("message"), adapter, xmldsig.ECDSASHA256, xmldsig.Policy{})
				}

				return cms.Sign(ctx, []byte("message"), []cms.Signer{{Key: adapter, CertificateDER: certificate}}, cms.SignOptions{})
			}

			value, err := sign()
			if err != nil || len(value) == 0 || provider.calls != 1 {
				t.Fatalf("provider context: %d calls, %v", provider.calls, err)
			}
			provider.cancel = cancel
			value, err = sign()
			if value != nil || !errors.Is(err, context.Canceled) || provider.calls != 2 {
				t.Fatalf("provider cancellation: %d bytes, %d calls, %v", len(value), provider.calls, err)
			}
		})
	}
}

func TestReaderSignatureRejectsProviderDigestMutation(t *testing.T) {
	key, _ := nativeIOSigner(t)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, method := range []struct {
		name string
		key  crypto.Signer
	}{{xmldsig.ECDSASHA256, key}, {xmldsig.Ed25519, edKey}, {xmldsig.Ed25519ph, edKey}} {
		t.Run(method.name, func(t *testing.T) {
			message := []byte("original message")
			provider := mutatingStreamSigner{method.key}
			policy := xmldsig.ModernPolicy()
			for _, sign := range []func() ([]byte, error){
				func() ([]byte, error) {
					return xmldsig.SignMessage(t.Context(), message, provider, method.name, policy)
				},
				func() ([]byte, error) {
					return xmldsig.SignMessageReader(t.Context(), bytes.NewReader(message), provider, method.name, policy)
				},
				func() ([]byte, error) {
					return xmldsig.SignMessageWithParameters(t.Context(), message, provider, method.name, xmldsig.SignatureParameters{}, policy)
				},
				func() ([]byte, error) {
					return xmldsig.SignMessageWithParametersReader(t.Context(), bytes.NewReader(message), provider, method.name, xmldsig.SignatureParameters{}, policy)
				},
			} {
				if value, err := sign(); value != nil || !errors.Is(err, xmldsig.ErrSignature) || string(message) != "original message" {
					t.Fatal("provider changed authenticated message", value, err, string(message))
				}
			}
		})
	}
}

func TestEd25519phReaderMemory(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	block := bytes.Repeat([]byte("data"), 1024)
	policy := xmldsig.ModernPolicy()
	for _, size := range []int{16 << 10, 8 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			source := func() io.Reader { return &repeatedInput{remaining: size, block: block} }
			hash := sha512.New()
			if _, err := io.Copy(hash, source()); err != nil {
				t.Fatal(err)
			}

			want, err := key.Sign(rand.Reader, hash.Sum(nil), crypto.SHA512)
			if err != nil {
				t.Fatal(err)
			}

			for _, operation := range []struct {
				name string
				run  func(io.Reader) error
			}{
				{"sign", func(src io.Reader) error {
					value, err := xmldsig.SignMessageReader(t.Context(), src, key, xmldsig.Ed25519ph, policy)
					if err == nil && !bytes.Equal(value, want) {
						return errors.New("Ed25519ph signature differs from Go")
					}
					return err
				}},
				{"verify", func(src io.Reader) error {
					return xmldsig.VerifyMessageReader(t.Context(), src, want, key.Public(), xmldsig.Ed25519ph, policy)
				}},
				{"sign parameters", func(src io.Reader) error {
					value, err := xmldsig.SignMessageWithParametersReader(t.Context(), src, key, xmldsig.Ed25519ph, xmldsig.SignatureParameters{}, policy)
					if err == nil && !bytes.Equal(value, want) {
						return errors.New("parameterized Ed25519ph signature differs from Go")
					}
					return err
				}},
				{"verify parameters", func(src io.Reader) error {
					return xmldsig.VerifyMessageWithParametersReader(t.Context(), src, want, key.Public(), xmldsig.Ed25519ph, xmldsig.SignatureParameters{}, policy)
				}},
			} {
				t.Run(operation.name, func(t *testing.T) {
					allocated := allocatedDuring(t, func() error {
						closed := false
						input := &streamingInput{source: source()}
						err := operation.run(&trackedInput{Reader: input, close: func() error { closed = true; return nil }})
						if input.bytes != size || closed {
							return errors.New("reader consumption or ownership changed")
						}
						return err
					})
					t.Logf("%d input bytes: %d allocated bytes", size, allocated)
					if allocated > 128<<10 {
						t.Fatalf("Ed25519ph retained message bytes: %d allocated", allocated)
					}
				})
			}
		})
	}
}

func TestEd25519MessageStorage(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := xmldsig.ModernPolicy()
	for _, size := range []int{16 << 10, 8 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			message := bytes.Repeat([]byte("x"), size)
			want := ed25519.Sign(key, message)
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"sign bytes", func() error {
					value, err := xmldsig.SignMessage(t.Context(), message, key, xmldsig.Ed25519, policy)
					if err == nil && !bytes.Equal(value, want) {
						return errors.New("pure Ed25519 signature differs from Go")
					}
					return err
				}},
				{"verify bytes", func() error {
					return xmldsig.VerifyMessage(t.Context(), message, want, key.Public(), xmldsig.Ed25519, policy)
				}},
				{"sign bytes pointer", func() error {
					value, err := xmldsig.SignMessage(t.Context(), message, &key, xmldsig.Ed25519, policy)
					if err == nil && !bytes.Equal(value, want) {
						return errors.New("pure Ed25519 pointer signature differs from Go")
					}
					return err
				}},
				{"sign parameter bytes", func() error {
					value, err := xmldsig.SignMessageWithParameters(t.Context(), message, key, xmldsig.Ed25519, xmldsig.SignatureParameters{}, policy)
					if err == nil && !bytes.Equal(value, want) {
						return errors.New("parameterized pure Ed25519 signature differs from Go")
					}
					return err
				}},
				{"verify parameter bytes", func() error {
					return xmldsig.VerifyMessageWithParameters(t.Context(), message, want, key.Public(), xmldsig.Ed25519, xmldsig.SignatureParameters{}, policy)
				}},
			} {
				t.Run(operation.name, func(t *testing.T) {
					allocated := allocatedDuring(t, operation.run)
					t.Logf("%d input bytes: %d allocated bytes", size, allocated)
					if allocated > 128<<10 {
						t.Fatalf("pure Ed25519 copied an already resident message: %d allocated", allocated)
					}
				})
			}

			// Pure Ed25519 must collect a non-replayable reader. Compare against
			// collection alone: race instrumentation changes Buffer growth costs.
			collection := allocatedDuring(t, func() error {
				var buffer bytes.Buffer
				_, err := io.CopyBuffer(struct{ io.Writer }{&buffer}, &repeatedInput{remaining: size, block: message[:4096]}, make([]byte, 32<<10))
				if err == nil && buffer.Len() != size {
					return errors.New("incomplete pure message fixture")
				}
				return err
			})
			allocated := allocatedDuring(t, func() error {
				value, err := xmldsig.SignMessageReader(t.Context(), &repeatedInput{remaining: size, block: message[:4096]}, key, xmldsig.Ed25519, policy)
				if err == nil && !bytes.Equal(value, want) {
					return errors.New("pure reader changed message")
				}
				return err
			})
			t.Logf("pure reader: %d input bytes, %d allocated bytes, %d collection baseline", size, allocated, collection)
			if allocated > collection+(128<<10) {
				t.Fatalf("pure Ed25519 reader retained excess copies: %d allocated", allocated)
			}

			limited := policy
			limited.MaxCanonicalBytes = size - 1
			if value, err := xmldsig.SignMessage(t.Context(), message, key, xmldsig.Ed25519, limited); value != nil || !errors.Is(err, xmldsig.ErrPolicy) {
				t.Fatal("borrowed message escaped byte budget", value, err)
			}
			if err := xmldsig.VerifyMessage(t.Context(), message, want, key.Public(), xmldsig.Ed25519, limited); !errors.Is(err, xmldsig.ErrPolicy) {
				t.Fatal("borrowed verification escaped byte budget", err)
			}
		})
	}
}

func TestEd25519phReaderPolicyAndErrors(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	policy := xmldsig.ModernPolicy()
	provider := &signingProvider{key: key}
	adapter, err := xmldsig.AdaptContextSigner(provider)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.WithValue(t.Context(), providerContextKey{}, provider)
	for _, parameters := range []bool{false, true} {
		t.Run(strconv.FormatBool(parameters), func(t *testing.T) {
			sign := func(ctx context.Context, src io.Reader, signer crypto.Signer, p xmldsig.Policy, params xmldsig.SignatureParameters) ([]byte, error) {
				if parameters {
					return xmldsig.SignMessageWithParametersReader(ctx, src, signer, xmldsig.Ed25519ph, params, p)
				}
				return xmldsig.SignMessageReader(ctx, src, signer, xmldsig.Ed25519ph, p)
			}
			verify := func(ctx context.Context, src io.Reader, value []byte, p xmldsig.Policy) error {
				if parameters {
					return xmldsig.VerifyMessageWithParametersReader(ctx, src, value, key.Public(), xmldsig.Ed25519ph, xmldsig.SignatureParameters{}, p)
				}
				return xmldsig.VerifyMessageReader(ctx, src, value, key.Public(), xmldsig.Ed25519ph, p)
			}

			value, err := sign(ctx, strings.NewReader("abc"), adapter, policy, xmldsig.SignatureParameters{})
			if err != nil || provider.inputSize != sha512.Size || provider.hash != crypto.SHA512 {
				t.Fatal("provider did not receive SHA-512 prehash", provider.inputSize, provider.hash, err)
			}
			calls := provider.calls

			for _, method := range []string{"sign", "verify"} {
				t.Run(method, func(t *testing.T) {
					run := func(ctx context.Context, src io.Reader, p xmldsig.Policy) error {
						if method == "verify" {
							return verify(ctx, src, value, p)
						}
						_, err := sign(ctx, src, adapter, p, xmldsig.SignatureParameters{})
						return err
					}
					failure := errors.New("input failed")
					closed := false
					source := &trackedInput{Reader: io.MultiReader(strings.NewReader("abc"), readFunc(func([]byte) (int, error) { return 0, failure })), close: func() error { closed = true; return nil }}
					if err := run(ctx, source, policy); !errors.Is(err, failure) || closed {
						t.Fatal("source error/ownership", err, closed)
					}

					limited := policy
					limited.MaxCanonicalBytes = 3
					input := &streamingInput{source: strings.NewReader("abcde")}
					if err := run(ctx, input, limited); !errors.Is(err, xmldsig.ErrPolicy) || input.bytes != 4 {
						t.Fatal("byte budget", err, input.bytes)
					}
					if err := run(ctx, strings.NewReader("abc"), limited); err != nil {
						t.Fatal("exact byte budget", err)
					}
					calls = provider.calls

					read := false
					unread := readFunc(func([]byte) (int, error) { read = true; return 0, io.EOF })
					if err := run(ctx, unread, xmldsig.DefaultPolicy()); !errors.Is(err, xmldsig.ErrPolicy) || read {
						t.Fatal("default policy consumed input", err, read)
					}

					canceled, cancel := context.WithCancel(ctx)
					cancel()
					if err := run(canceled, unread, policy); !errors.Is(err, context.Canceled) || read {
						t.Fatal("canceled operation read input", err, read)
					}

					canceled, cancel = context.WithCancel(ctx)
					defer cancel()
					reader := strings.NewReader(strings.Repeat("x", 64<<10))
					input = &streamingInput{source: readFunc(func(p []byte) (int, error) { n, err := reader.Read(p); cancel(); return n, err })}
					if err := run(canceled, input, policy); !errors.Is(err, context.Canceled) || input.bytes >= 64<<10 {
						t.Fatal("cancellation did not stop reading", err, input.bytes)
					}
					if provider.calls != calls {
						t.Fatal("provider called after failed input", provider.calls, calls)
					}
				})
			}

			read := false
			unread := readFunc(func([]byte) (int, error) { read = true; return 0, io.EOF })
			if value, err := sign(ctx, unread, &ecdsa.PrivateKey{}, policy, xmldsig.SignatureParameters{}); value != nil || !errors.Is(err, xmldsig.ErrKey) || read {
				t.Fatal("invalid key read input", value, err, read)
			}
			if parameters {
				for _, params := range []xmldsig.SignatureParameters{{PSS: &xmldsig.PSSParameters{}}, {HMACOutputLength: 256}} {
					if value, err := sign(ctx, unread, adapter, policy, params); value != nil || !errors.Is(err, xmldsig.ErrStructure) || read {
						t.Fatal("foreign parameters read input", value, err, read)
					}
				}
			}
		})
	}
}

func TestCanonicalNamespaceWorkingStorage(t *testing.T) {
	for _, count := range []int{128, 8192} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			raw := `<r xmlns:p="urn:p">` + strings.Repeat(`<p:v xmlns:p="urn:p" a="x">v</p:v>`, count) + `</r>`
			doc, err := document.ParseReader(t.Context(), strings.NewReader(raw), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			set, err := doc.AllNodes(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, algorithm := range []string{c14n.Exclusive, c14n.Canonical10, c14n.Canonical11} {
				want := `<r xmlns:p="urn:p">` + strings.Repeat(`<p:v a="x">v</p:v>`, count) + `</r>`
				if algorithm == c14n.Exclusive {
					want = `<r>` + strings.Repeat(`<p:v xmlns:p="urn:p" a="x">v</p:v>`, count) + `</r>`
				}
				expected := sha256.Sum256([]byte(want))
				for _, explicitSet := range []bool{false, true} {
					allocated := allocatedDuring(t, func() error {
						hash := sha256.New()
						var err error
						if explicitSet {
							err = c14n.WriteNodeSet(t.Context(), hash, set, c14n.Options{Algorithm: algorithm})
						} else {
							err = c14n.WriteDocument(t.Context(), hash, doc, c14n.Options{Algorithm: algorithm})
						}
						if err == nil && !bytes.Equal(hash.Sum(nil), expected[:]) {
							return errors.New("canonical namespace output changed")
						}
						return err
					})
					t.Logf("%s nodeset=%v, %d elements: %d allocated", algorithm, explicitSet, count, allocated)
					// Two prefixed tag names per element remain small strings. Allow
					// 16-byte allocator slots under -race, plus fixed working storage.
					if allocated > uint64(count)*32+(64<<10) {
						t.Fatal("canonicalization copied namespace maps for each sibling", allocated)
					}
				}
			}
		})
	}
}

func TestReferenceNodeSetWorkingStorage(t *testing.T) {
	const count = 8192
	doc, err := document.ParseReader(t.Context(), strings.NewReader(`<r>`+strings.Repeat(`<v a="value">eHh4</v>`, count)+`</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	set, err := doc.AllNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	data, err := reference.Nodes(set)
	if err != nil {
		t.Fatal(err)
	}
	base64Chain := []reference.Transform{{Algorithm: reference.Base64}}
	xpathChain := []reference.Transform{{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "true()"}}}}
	for _, tc := range []struct {
		name       string
		transforms []reference.Transform
		options    reference.Options
		want       string
	}{
		{"Base64", base64Chain, reference.Options{}, strings.Repeat("xxx", count)},
		{"XPath subset", xpathChain, reference.Options{Extension: identityXPath{}, AllowedTransforms: []string{reference.XPath, c14n.Canonical10}}, `<r>` + strings.Repeat(`<v a="value">eHh4</v>`, count) + `</r>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := sha256.Sum256([]byte(tc.want))
			allocated := allocatedDuring(t, func() error {
				hash := sha256.New()
				report, err := reference.Write(t.Context(), hash, data, tc.transforms, tc.options)
				if err == nil && (report.Size() != len(tc.want) || !bytes.Equal(hash.Sum(nil), expected[:])) {
					return errors.New("reference output changed")
				}
				return err
			})
			t.Logf("%d selected nodes: %d allocated", set.Len(), allocated)
			if allocated > 128<<10 {
				t.Fatal("reference materialized a sorted copy of all selected nodes", allocated)
			}
			failure := errors.New("early sink failure")
			allocated = allocatedDuring(t, func() error {
				report, err := reference.Write(t.Context(), &prefixFailure{remaining: 1, failure: failure}, data, tc.transforms, tc.options)
				if report != nil || !errors.Is(err, failure) {
					return errors.New("early error/report contract changed")
				}
				return nil
			})
			if allocated > 128<<10 {
				t.Fatal("early failure allocated a complete selection copy", allocated)
			}
		})
	}
}

func TestSignatureTemplateUsesResultParserStorage(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		t.Run(strconv.FormatBool(embedded), func(t *testing.T) {
			large, err := document.ParseReader(t.Context(), strings.NewReader(`<r ID="root">`+strings.Repeat(`<v a="x">kept</v>`, 8192)+`</r>`), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			small, err := document.ParseReader(t.Context(), strings.NewReader(`<r ID="container"/>`), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			doc := large
			spec := xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: "#root", Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}}
			if embedded {
				doc = small
				spec.References[0].URI = "#container"
				spec.Objects = []xmldsig.ObjectTemplate{{ID: "object", XML: large}}
			}
			built, _, err := xmldsig.BuildTemplate(t.Context(), doc, doc.Root(), spec)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := built.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			baseline := allocatedDuring(t, func() error {
				_, err := document.ParseReader(t.Context(), bytes.NewReader(wire), document.DefaultLimits())
				return err
			})
			allocated := allocatedDuring(t, func() error { _, _, err := xmldsig.BuildTemplate(t.Context(), doc, doc.Root(), spec); return err })
			t.Logf("template embedded=%v: %d allocated, %d result parser baseline", embedded, allocated, baseline)
			if allocated > baseline+(256<<10) {
				t.Fatal("template cloned source or embedded XML", allocated, baseline)
			}
			if len(xmldsig.Signatures(doc)) != 0 || len(xmldsig.Signatures(large)) != 0 {
				t.Fatal("template mutated the source snapshot")
			}
		})
	}
}

func TestEnvelopedSignatureWorkingStorage(t *testing.T) {
	key, _ := nativeIOSigner(t)
	const raw = `<r ID="root" xmlns:p="urn:p">`
	doc, err := document.ParseReader(t.Context(), strings.NewReader(raw+strings.Repeat(`<p:v a="x">kept</p:v>`, 8192)+`</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := xmldsig.SignEnveloped(t.Context(), doc, key, xmldsig.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := signed.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	parserBaseline := allocatedDuring(t, func() error {
		_, err := document.ParseReader(t.Context(), bytes.NewReader(wire), document.DefaultLimits())
		return err
	})
	referenceBaseline := allocatedDuring(t, func() error {
		set, err := doc.Root().Subtree(t.Context())
		if err != nil {
			return err
		}
		return c14n.WriteNodeSet(t.Context(), sha256.New(), set, c14n.Options{})
	})
	allocated := allocatedDuring(t, func() error {
		_, err := xmldsig.SignEnveloped(t.Context(), doc, key, xmldsig.SignOptions{})
		return err
	})
	t.Logf("enveloped: %d allocated, %d result parsing + %d node-set baseline", allocated, parserBaseline, referenceBaseline)
	if allocated > parserBaseline+referenceBaseline+(512<<10) {
		t.Fatal("enveloped signing cloned the source tree", allocated, parserBaseline, referenceBaseline)
	}
	if result, err := xmldsig.Verify(t.Context(), signed, key.Public(), xmldsig.VerifyOptions{}); result == nil || err != nil {
		t.Fatal("signature failed verification", err)
	}
	if len(xmldsig.Signatures(doc)) != 0 {
		t.Fatal("signing changed the source")
	}
}

func TestReferenceRejectsOversizedProgramBeforeCopying(t *testing.T) {
	style := reference.Transform{Algorithm: reference.XSLT, Stylesheet: bytes.Repeat([]byte("x"), 8<<20)}
	read := false
	input := readFunc(func([]byte) (int, error) { read = true; return 0, io.EOF })
	allocated := allocatedDuring(t, func() error {
		report, err := reference.WriteReader(t.Context(), io.Discard, input, []reference.Transform{style}, reference.Options{Extension: identityXPath{}, AllowedTransforms: []string{reference.XSLT}})
		if report != nil || err == nil || read {
			return errors.New("invalid program was executed")
		}
		return nil
	})
	if allocated > 64<<10 {
		t.Fatal("oversized stylesheet copied before rejection", allocated)
	}
}

func TestProgramFingerprintWorkingStorage(t *testing.T) {
	style := []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><r>` + strings.Repeat("x", 512<<10) + `</r></xsl:template></xsl:stylesheet>`)
	baseline := allocatedDuring(t, func() error {
		_, err := document.Parse(t.Context(), style, document.DefaultLimits())
		return err
	})
	allocated := allocatedDuring(t, func() error {
		_, err := reference.ProgramFingerprint(reference.Transform{Algorithm: reference.XSLT, Stylesheet: style})
		return err
	})
	t.Logf("program fingerprint: %d allocated, %d XML parser baseline", allocated, baseline)
	if allocated > baseline+(128<<10) {
		t.Fatal("fingerprint retained source/canonical/JSON copies or reparsed source", allocated, baseline)
	}
}

func TestExternalTransformCacheAndResultOwnership(t *testing.T) {
	key, _ := nativeIOSigner(t)
	const uri = "urn:cache:source"
	var refs []xmldsig.ReferenceTemplate
	for _, marker := range []string{"one", "two", "one"} {
		style := []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:text>` + marker + `</xsl:text></xsl:template></xsl:stylesheet>`)
		refs = append(refs, xmldsig.ReferenceTemplate{URI: uri, Transforms: []reference.Transform{{Algorithm: reference.XSLT, Stylesheet: style}}})
	}
	template, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: refs})
	if err != nil {
		t.Fatal(err)
	}
	opened, closed := 0, 0
	resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		opened++
		return &trackedInput{Reader: strings.NewReader("body"), close: func() error { closed++; return nil }}, nil
	})
	options := xmldsig.SignatureOptions{ExpectedURIs: []string{uri, uri, uri}, External: &xmldsig.ExternalReferences{Resolver: resolver, AllowedURIs: []string{uri}}, Processing: reference.Options{Extension: markedStylesheet{}, AllowedTransforms: []string{reference.XSLT, c14n.Exclusive}}}
	signed, err := xmldsig.SignTemplate(t.Context(), template, selected, key, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}
	result, err := xmldsig.VerifySignature(t.Context(), signed, signed.Root(), key.Public(), options)
	if err != nil {
		t.Fatal(err)
	}
	if opened != 6 || closed != opened {
		t.Fatal("equivalent/different programs changed cache or reader lifecycle", opened, closed)
	}
	for i, ref := range result.References() {
		want := "onebody"
		if i == 1 {
			want = "twobody"
		}
		expected := sha256.Sum256([]byte(want))
		if !bytes.Equal(ref.Digest(), expected[:]) {
			t.Fatal("different stylesheets shared processing evidence", i, ref.Digest())
		}
		owned := ref.Transforms()
		clear(owned[0].Stylesheet)
		var replay bytes.Buffer
		if n, err := ref.WriteDigestInput(t.Context(), &replay); err != nil || n != int64(len(want)) || replay.String() != want {
			t.Fatal("mutable accessor changed replay or its integrity check", n, err, replay.String())
		}
	}
}

func TestTemplateRejectsBinaryBeforeEncoding(t *testing.T) {
	blob := make([]byte, 8<<20)
	for _, objects := range [][]xmldsig.ObjectTemplate{
		{{ID: "large", Binary: blob}},
		{{ID: "one", Binary: blob[:4<<20]}, {ID: "two", Binary: blob[4<<20:]}},
	} {
		spec := xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, Objects: objects, References: []xmldsig.ReferenceTemplate{{URI: "urn:binary"}}}
		allocated := allocatedDuring(t, func() error {
			doc, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, spec)
			if doc != nil || selected.Valid() || !errors.Is(err, xmldsig.ErrPolicy) {
				return errors.New("encoded template byte budget lost")
			}
			return nil
		})
		if allocated > 64<<10 {
			t.Fatal("binary Objects encoded before aggregate XML byte check", allocated)
		}
	}
}

type providerContextKey struct{}

type signingProvider struct {
	key       crypto.Signer
	calls     int
	cancel    context.CancelFunc
	inputSize int
	hash      crypto.Hash
}

func (p *signingProvider) Public() crypto.PublicKey { return p.key.Public() }

func (p *signingProvider) Sign(ctx context.Context, random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	if ctx.Value(providerContextKey{}) != p {
		return nil, errors.New("caller context did not reach provider")
	}

	p.calls++
	p.inputSize, p.hash = len(digest), options.HashFunc()
	value, err := p.key.Sign(random, digest, options)
	if p.cancel != nil {
		p.cancel()
	}

	return value, err
}

type mutatingStreamSigner struct{ crypto.Signer }

func (s mutatingStreamSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	digest[0] ^= 1
	return s.Signer.Sign(random, digest, options)
}

type identityXPath struct{}

func (identityXPath) Validate(context.Context, reference.Transform) error { return nil }

func (identityXPath) Apply(_ context.Context, _ reference.Transform, data reference.Data, _ reference.ExtensionContext) (reference.Data, error) {
	return data, nil
}

type markedStylesheet struct{}

func (markedStylesheet) Validate(ctx context.Context, tr reference.Transform) error {
	if !bytes.Contains(tr.Stylesheet, []byte(">one<")) && !bytes.Contains(tr.Stylesheet, []byte(">two<")) {
		return reference.ErrPolicy
	}
	return ctx.Err()
}

func (markedStylesheet) Apply(context.Context, reference.Transform, reference.Data, reference.ExtensionContext) (reference.Data, error) {
	return reference.Data{}, errors.New("reader interface was not used")
}

func (markedStylesheet) WriteTransform(ctx context.Context, dst io.Writer, src io.Reader, tr reference.Transform, _ reference.ExtensionContext) error {
	marker := "one"
	if bytes.Contains(tr.Stylesheet, []byte(">two<")) {
		marker = "two"
	}
	if _, err := io.WriteString(dst, marker); err != nil {
		return err
	}
	_, err := io.CopyBuffer(dst, src, make([]byte, 4096))
	return errors.Join(err, ctx.Err())
}
