package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmldsig"
)

const input = `<app:Root xmlns:app="urn:app" xmlns:q="urn:q" ID="root"><app:Item ID="one">hello</app:Item><app:Item ID="two">world</app:Item></app:Root>`

const nameOne = "one"

func TestAlgorithmsAndReferences(t *testing.T) {
	key := rsaKey(t)

	tests := []struct {
		name, method, digest string
		key                  crypto.Signer
	}{
		{"RSA256", xmldsig.RSASHA256, xmldsig.SHA256, key},
		{"RSA384", xmldsig.RSASHA384, xmldsig.SHA384, key},
		{"RSA512", xmldsig.RSASHA512, xmldsig.SHA512, key},
		{"EC256", xmldsig.ECDSASHA256, xmldsig.SHA256, ecKey(t, elliptic.P256())},
		{"EC384", xmldsig.ECDSASHA384, xmldsig.SHA384, ecKey(t, elliptic.P384())},
		{"EC521", xmldsig.ECDSASHA512, xmldsig.SHA512, ecKey(t, elliptic.P521())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := parse(t, input)
			before := xmlString(t, original)

			signed := sign(t, tt.key, original, xmldsig.SignOptions{SignatureMethod: tt.method, DigestMethod: tt.digest, ReferenceIDs: []string{nameRoot, nameOne, "two"}, InclusivePrefixes: []string{"q"}})
			if xmlString(t, original) != before {
				t.Fatal("signing mutated input")
			}
			// Verify a fresh parse, not the in-memory representation used by signer.
			d := parse(t, xmlString(t, signed))

			result, err := xmldsig.Verify(context.Background(), d, tt.key.Public(), xmldsig.VerifyOptions{ExpectedRoot: document.Name{Space: "urn:app", Local: "Root"}})
			if err != nil {
				t.Fatal(err)
			}

			if len(result.References()) != 3 {
				t.Fatal("not all references reported")
			}

			if result.SignatureMethod() != tt.method || len(result.KeyFingerprintSHA256()) != 64 {
				t.Fatal("invalid result metadata")
			}

			if !result.CoversElement(d.Root()) || !result.CoversElement(d.Root().Children()[0]) {
				t.Fatal("payload not covered")
			}

			children := d.Root().Children()
			if result.CoversElement(children[len(children)-1]) {
				t.Fatal("signature covered by root reference")
			}

			if result.CoversElement(original.Root()) {
				t.Fatal("coverage crossed snapshots")
			}

			refs := result.References()
			copyBytes := digestInput(t, refs[0])
			copyBytes[0] = '!'

			if digestInput(t, refs[0])[0] != '<' {
				t.Fatal("canonical bytes alias state")
			}

			if bytes.Contains(digestInput(t, refs[0]), []byte("<ds:Signature")) {
				t.Fatal("enveloped transform failed")
			}
		})
	}
}

func TestTamperingAndStructure(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	signed := sign(t, key, parse(t, input), xmldsig.SignOptions{ReferenceIDs: []string{nameRoot, nameOne}})
	src := xmlString(t, signed)

	cases := []struct {
		name   string
		change func(string) string
		want   error
	}{
		{"payload", func(s string) string { return strings.Replace(s, "hello", "EVIL", 1) }, xmldsig.ErrDigest},
		{"duplicate ID", func(s string) string { return strings.Replace(s, `ID="two"`, `ID="one"`, 1) }, xmldsig.ErrReference},
		{"external reference", func(s string) string {
			return strings.Replace(s, `URI="#one"`, `URI="https://invalid.example/data"`, 1)
		}, xmldsig.ErrReference},
		{"empty reference", func(s string) string { return strings.Replace(s, `URI="#root"`, `URI=""`, 1) }, xmldsig.ErrReference},
		{"root renamed", func(s string) string { return strings.ReplaceAll(s, "app:Root", "app:Different") }, xmldsig.ErrPolicy},
		{"unsupported method", func(s string) string { return strings.Replace(s, xmldsig.ECDSASHA256, "urn:unknown:method", 1) }, xmldsig.ErrAlgorithm},
		{"wrapping", func(s string) string { return "<Wrapper ID='wrapper'>" + s + "<Payload>EVIL</Payload></Wrapper>" }, xmldsig.ErrStructure},
		{"wrong Signature namespace", func(s string) string {
			return strings.Replace(s, `xmlns:ds="`+xmldsig.Namespace+`"`, `xmlns:ds="urn:fake"`, 1)
		}, xmldsig.ErrStructure},
		{"extra SignedInfo", func(s string) string {
			return strings.Replace(s, "</ds:Signature>", "<ds:SignedInfo/></ds:Signature>", 1)
		}, xmldsig.ErrStructure},
		{"nested Signature", func(s string) string {
			return strings.Replace(s, "hello", `<ds:Signature xmlns:ds="`+xmldsig.Namespace+`"/>`, 1)
		}, xmldsig.ErrStructure},
		{"missing reference target", func(s string) string { return strings.Replace(s, `URI="#one"`, `URI="#missing"`, 1) }, xmldsig.ErrReference},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			d := parse(t, tt.change(src))

			opt := xmldsig.VerifyOptions{}
			if tt.name == "root renamed" {
				opt.ExpectedRoot = document.Name{Space: "urn:app", Local: "Root"}
			}

			result, err := xmldsig.Verify(context.Background(), d, key.Public(), opt)
			if result != nil || !errors.Is(err, tt.want) {
				t.Fatalf("result %v error %v, want %v", result, err, tt.want)
			}
		})
	}

	wrong := ecKey(t, elliptic.P256())
	if _, err := xmldsig.Verify(context.Background(), signed, wrong.Public(), xmldsig.VerifyOptions{}); !errors.Is(err, xmldsig.ErrSignature) {
		t.Fatal(err)
	}

	if _, err := xmldsig.Verify(context.Background(), signed, nil, xmldsig.VerifyOptions{}); !errors.Is(err, xmldsig.ErrKey) {
		t.Fatal(err)
	}
}

func TestExternalSignerAndErrors(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	adapter := &controlledSigner{Signer: key}

	signed := sign(t, adapter, parse(t, input), xmldsig.SignOptions{})
	if adapter.calls != 1 {
		t.Fatal(adapter.calls)
	}

	if _, err := xmldsig.Verify(context.Background(), signed, key.Public(), xmldsig.VerifyOptions{}); err != nil {
		t.Fatal(err)
	}

	var nilKey *rsa.PrivateKey
	if _, err := xmldsig.SignEnveloped(context.Background(), parse(t, input), nilKey, xmldsig.SignOptions{}); err == nil {
		t.Fatal("typed nil signer accepted")
	}

	fail := errors.New("HSM unavailable")
	if _, err := xmldsig.SignEnveloped(context.Background(), parse(t, input), failingSigner{key, fail}, xmldsig.SignOptions{}); !errors.Is(err, fail) {
		t.Fatal(err)
	}

	if _, err := xmldsig.SignEnveloped(context.Background(), parse(t, input), badSigner{key}, xmldsig.SignOptions{}); !errors.Is(err, xmldsig.ErrSignature) {
		t.Fatal(err)
	}
}

func TestPolicyAndID(t *testing.T) {
	key := ecKey(t, elliptic.P256())

	tests := []struct {
		name, src string
		opt       xmldsig.SignOptions
	}{
		{"missing ID", `<r/>`, xmldsig.SignOptions{}},
		{"duplicate ID", `<r ID="r"><c ID="r"/></r>`, xmldsig.SignOptions{}},
		{"not NCName", `<r ID="1bad"/>`, xmldsig.SignOptions{}},
		{"root omitted", input, xmldsig.SignOptions{ReferenceIDs: []string{nameOne}}},
		{"too many refs", input, xmldsig.SignOptions{ReferenceIDs: []string{nameRoot, nameOne}, Policy: xmldsig.Policy{MaxReferences: 1}}},
		{"duplicate ref", input, xmldsig.SignOptions{ReferenceIDs: []string{nameRoot, nameRoot}}},
		{"unsupported digest", input, xmldsig.SignOptions{DigestMethod: "urn:unknown"}},
		{"algorithm mismatch", input, xmldsig.SignOptions{SignatureMethod: xmldsig.RSASHA256}},
		{"budget", input, xmldsig.SignOptions{Policy: xmldsig.Policy{MaxCanonicalBytes: 1}}},
		{"bad prefix", input, xmldsig.SignOptions{InclusivePrefixes: []string{"bad:prefix"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := xmldsig.SignEnveloped(context.Background(), parse(t, tt.src), key, tt.opt); err == nil {
				t.Fatal("invalid signing input accepted")
			}
		})
	}

	id := document.Name{Space: "urn:id", Local: "id"}

	signed := sign(t, key, parse(t, `<r xmlns:i="urn:id" i:id="root"><c/></r>`), xmldsig.SignOptions{IDAttribute: id})
	if _, err := xmldsig.Verify(context.Background(), signed, key.Public(), xmldsig.VerifyOptions{IDAttribute: id}); err != nil {
		t.Fatal(err)
	}

	if _, err := xmldsig.Verify(context.Background(), signed, key.Public(), xmldsig.VerifyOptions{}); err == nil {
		t.Fatal("ID attribute was guessed")
	}

	if _, err := xmldsig.SignEnveloped(context.Background(), signed, key, xmldsig.SignOptions{}); err == nil {
		t.Fatal("existing signature accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := xmldsig.SignEnveloped(ctx, parse(t, input), key, xmldsig.SignOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}

	if _, err := xmldsig.Verify(ctx, signed, key.Public(), xmldsig.VerifyOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestECDSAIsNotDER(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	signed := sign(t, key, parse(t, input), xmldsig.SignOptions{})
	s := xmlString(t, signed)
	start := strings.Index(s, "<ds:SignatureValue>") + len("<ds:SignatureValue>")
	end := strings.Index(s, "</ds:SignatureValue>")

	raw, err := base64.StdEncoding.DecodeString(s[start:end])
	if err != nil {
		t.Fatal(err)
	}

	if len(raw) != 64 {
		t.Fatalf("XMLDSig ECDSA signature has %d bytes, want 64", len(raw))
	}

	pair := struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])}

	der, err := asn1.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}

	changed := parse(t, s[:start]+base64.StdEncoding.EncodeToString(der)+s[end:])
	if _, err := xmldsig.Verify(context.Background(), changed, key.Public(), xmldsig.VerifyOptions{}); !errors.Is(err, xmldsig.ErrSignature) {
		t.Fatal(err)
	}
}

func TestKeyInfoDoesNotEstablishTrust(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	signed := sign(t, key, parse(t, input), xmldsig.SignOptions{})
	// KeyInfo is inside the excluded Signature subtree. It does not choose a key.
	src := strings.Replace(xmlString(t, signed), "</ds:Signature>", `<ds:KeyInfo><ds:KeyName>trusted-admin</ds:KeyName><ds:RetrievalMethod URI="https://invalid.example/key"/></ds:KeyInfo></ds:Signature>`, 1)

	doc := parse(t, src)
	if _, err := xmldsig.Verify(context.Background(), doc, key.Public(), xmldsig.VerifyOptions{}); err != nil {
		t.Fatal(err)
	}

	if _, err := xmldsig.Verify(context.Background(), doc, ecKey(t, elliptic.P256()).Public(), xmldsig.VerifyOptions{}); !errors.Is(err, xmldsig.ErrSignature) {
		t.Fatal(err)
	}
}

func TestVerifyConcurrency(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	signed := sign(t, key, parse(t, input), xmldsig.SignOptions{})

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 10 {
				if _, err := xmldsig.Verify(context.Background(), signed, key.Public(), xmldsig.VerifyOptions{}); err != nil {
					t.Error(err)
				}
			}
		})
	}

	wg.Wait()
}

func TestZeroDocuments(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	for _, d := range []*document.Document{nil, {}} {
		if _, err := xmldsig.SignEnveloped(context.Background(), d, key, xmldsig.SignOptions{}); err == nil {
			t.Fatal("empty document signed")
		}

		if _, err := xmldsig.Verify(context.Background(), d, key.Public(), xmldsig.VerifyOptions{}); err == nil {
			t.Fatal("empty document verified")
		}
	}
}

func FuzzVerify(f *testing.F) {
	// All fuzz workers must share the SAME public key and signed seed. Generating
	// a new key in each process makes the coordinator's valid seed invalid in
	// the worker, defeating coverage of the successful verification path.
	prefix := filepath.Join("..", "testdata", "interop", "ec256")

	keyPEM, err := os.ReadFile(prefix + ".pub.pem")
	if err != nil {
		f.Fatal(err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		f.Fatal("invalid public key fixture")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		f.Fatal(err)
	}

	for _, suffix := range []string{".xml", ".bad-second-digest.xml"} {
		data, err := os.ReadFile(prefix + suffix)
		if err != nil {
			f.Fatal(err)
		}

		f.Add(data)
	}

	f.Add([]byte(`<r ID="root"/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}

		doc, err := document.Parse(t.Context(), data, document.DefaultLimits())
		if err != nil {
			return
		}

		result, err := xmldsig.Verify(context.Background(), doc, key, xmldsig.VerifyOptions{})
		if err == nil && (result == nil || !result.CoversElement(doc.Root())) {
			t.Fatal("success without root coverage")
		}
	})
}

func TestModernSignatureMethods(t *testing.T) {
	rsaKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}

	_, edKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	tests := []struct {
		name, method string
		key          crypto.Signer
		hash         crypto.Hash
	}{
		{"pss256", xmldsig.RSAPSSSHA256, rsaKey, crypto.SHA256},
		{"pss384", xmldsig.RSAPSSSHA384, rsaKey, crypto.SHA384},
		{"pss512", xmldsig.RSAPSSSHA512, rsaKey, crypto.SHA512},
		{"ed25519", xmldsig.Ed25519, edKey, 0},
		{"ed25519ph", xmldsig.Ed25519ph, edKey, crypto.SHA512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { testModernSignatureMethodsCase(t, &tc, &edKey, &rsaKey) })
	}

	signed, err := xmldsig.SignEnveloped(t.Context(), graphDoc(t, `<r ID="r">payload</r>`), edKey, xmldsig.SignOptions{Policy: xmldsig.ModernPolicy()})
	if err != nil {
		t.Fatal(err)
	}

	result, err := xmldsig.Verify(t.Context(), signed, edKey.Public(), xmldsig.VerifyOptions{Policy: xmldsig.ModernPolicy()})
	if err != nil || result.SignatureMethod() != xmldsig.Ed25519 {
		t.Fatal("default Ed25519 method changed", result, err)
	}
}

func testModernSignatureMethodsCase(t *testing.T, tc *struct {
	name   string
	method string
	key    crypto.Signer
	hash   crypto.Hash
}, edKey *ed25519.PrivateKey, rsaKey **rsa.PrivateKey,
) {
	ctx := context.Background()
	d := graphDoc(t, `<r ID="r">payload</r>`)

	signed, e := xmldsig.SignEnveloped(ctx, d, tc.key, xmldsig.SignOptions{SignatureMethod: tc.method, Policy: xmldsig.ModernPolicy()})
	if e != nil {
		t.Fatal(e)
	}

	if _, e = xmldsig.Verify(ctx, signed, tc.key.Public(), xmldsig.VerifyOptions{Policy: xmldsig.ModernPolicy()}); e != nil {
		t.Fatal(e)
	}

	if _, e = xmldsig.Verify(ctx, signed, tc.key.Public(), xmldsig.VerifyOptions{}); !errors.Is(e, xmldsig.ErrPolicy) {
		t.Fatalf("new method implicitly enabled: %v", e)
	}

	message := []byte("precise bytes")

	signature, e := xmldsig.SignMessage(ctx, message, tc.key, tc.method, xmldsig.ModernPolicy())
	if e != nil {
		t.Fatal(e)
	}

	if tc.hash == 0 {
		if !ed25519.Verify(edKey.Public().(ed25519.PublicKey), message, signature) {
			t.Fatal("not pure Ed25519")
		}
	} else if tc.method == xmldsig.Ed25519ph {
		digest := sha512.Sum512(message)
		if err := ed25519.VerifyWithOptions(edKey.Public().(ed25519.PublicKey), digest[:], signature, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
			t.Fatal("not Ed25519ph", err)
		}
	} else {
		h := tc.hash.New()
		h.Write(message)

		if e := rsa.VerifyPSS(&(*rsaKey).PublicKey, tc.hash, h.Sum(nil), signature, &rsa.PSSOptions{Hash: tc.hash, SaltLength: tc.hash.Size()}); e != nil {
			t.Fatal(e)
		}

		wrongSalt, e := rsa.SignPSS(rand.Reader, *rsaKey, tc.hash, h.Sum(nil), &rsa.PSSOptions{Hash: tc.hash, SaltLength: 8})
		if e != nil {
			t.Fatal(e)
		}

		if e = xmldsig.VerifyMessage(ctx, message, wrongSalt, &(*rsaKey).PublicKey, tc.method, xmldsig.ModernPolicy()); !errors.Is(e, xmldsig.ErrSignature) {
			t.Fatalf("wrong PSS salt accepted: %v", e)
		}
	}

	if e = xmldsig.VerifyMessage(ctx, []byte("other bytes"), signature, tc.key.Public(), tc.method, xmldsig.ModernPolicy()); !errors.Is(e, xmldsig.ErrSignature) {
		t.Fatalf("tamper accepted: %v", e)
	}
}

func TestContextSignerAdapter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider := &contextTestSigner{key: graphKey(t)}

	adapter, e := xmldsig.AdaptContextSigner(provider)
	if e != nil {
		t.Fatal(e)
	}

	if _, e = xmldsig.SignMessage(ctx, []byte("m"), adapter, xmldsig.ECDSASHA256, xmldsig.Policy{}); e != nil || provider.received != ctx {
		t.Fatalf("context lost: %v", e)
	}

	provider.cancel = cancel

	sig, e := xmldsig.SignMessage(ctx, []byte("m"), adapter, xmldsig.ECDSASHA256, xmldsig.Policy{})
	if sig != nil || !errors.Is(e, context.Canceled) {
		t.Fatalf("cancel ignored: %v", e)
	}

	var nilProvider *contextTestSigner
	if _, e = xmldsig.AdaptContextSigner(nilProvider); !errors.Is(e, xmldsig.ErrKey) {
		t.Fatal("typed nil accepted")
	}
}

func TestModernTemplate(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	text := "ed object"

	opt := xmldsig.SignatureOptions{Policy: xmldsig.ModernPolicy()}

	for _, method := range []string{xmldsig.Ed25519, xmldsig.Ed25519ph} {
		t.Run(method, func(t *testing.T) {
			draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: method, References: []xmldsig.ReferenceTemplate{{URI: "#a", Transforms: graphC14N()}}, Objects: []xmldsig.ObjectTemplate{{ID: "a", Text: &text}}})
			if err != nil {
				t.Fatal(err)
			}

			signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: opt})
			if err != nil {
				t.Fatal(err)
			}

			if _, err := xmldsig.VerifySignature(t.Context(), signed, signed.Root(), key.Public(), opt); err != nil {
				t.Fatal(err)
			}

			children := signed.Root().Children()

			value, err := base64.StdEncoding.DecodeString(children[1].Text())
			if err != nil {
				t.Fatal(err)
			}

			var canonical bytes.Buffer
			if err := c14n.WriteElement(t.Context(), &canonical, children[0], c14n.Options{}); err != nil {
				t.Fatal(err)
			}

			message := canonical.Bytes()
			options := &ed25519.Options{}

			if method == xmldsig.Ed25519ph {
				digest := sha512.Sum512(message)
				message = digest[:]
				options.Hash = crypto.SHA512
			}

			if err := ed25519.VerifyWithOptions(key.Public().(ed25519.PublicKey), message, value, options); err != nil {
				t.Fatal("Go verification of canonical SignedInfo", err)
			}
		})
	}
}

func TestEd25519phRFC8032(t *testing.T) {
	// RFC 8032 section 7.3: the prehashed "abc" test vector.
	seed, err := hex.DecodeString("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
	if err != nil {
		t.Fatal(err)
	}

	want, err := hex.DecodeString("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")
	if err != nil {
		t.Fatal(err)
	}

	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public()
	message := []byte("abc")
	policy := xmldsig.ModernPolicy()

	for _, operation := range []struct {
		name string
		sign func() ([]byte, error)
	}{
		{"bytes", func() ([]byte, error) {
			return xmldsig.SignMessage(t.Context(), message, key, xmldsig.Ed25519ph, policy)
		}},
		{"reader", func() ([]byte, error) {
			return xmldsig.SignMessageReader(t.Context(), iotest.OneByteReader(strings.NewReader("abc")), key, xmldsig.Ed25519ph, policy)
		}},
		{"parameters bytes", func() ([]byte, error) {
			return xmldsig.SignMessageWithParameters(t.Context(), message, key, xmldsig.Ed25519ph, xmldsig.SignatureParameters{}, policy)
		}},
		{"parameters reader", func() ([]byte, error) {
			return xmldsig.SignMessageWithParametersReader(t.Context(), iotest.DataErrReader(strings.NewReader("abc")), key, xmldsig.Ed25519ph, xmldsig.SignatureParameters{}, policy)
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			value, err := operation.sign()
			if err != nil || !bytes.Equal(value, want) {
				t.Fatalf("RFC signature = %x, %v", value, err)
			}
		})
	}

	for _, err := range []error{
		xmldsig.VerifyMessage(t.Context(), message, want, public, xmldsig.Ed25519ph, policy),
		xmldsig.VerifyMessageReader(t.Context(), strings.NewReader("abc"), want, public, xmldsig.Ed25519ph, policy),
		xmldsig.VerifyMessageWithParameters(t.Context(), message, want, public, xmldsig.Ed25519ph, xmldsig.SignatureParameters{}, policy),
		xmldsig.VerifyMessageWithParametersReader(t.Context(), strings.NewReader("abc"), want, public, xmldsig.Ed25519ph, xmldsig.SignatureParameters{}, policy),
	} {
		if err != nil {
			t.Fatal("RFC verification", err)
		}
	}

	digest := sha512.Sum512(message)
	if err := ed25519.VerifyWithOptions(public.(ed25519.PublicKey), digest[:], want, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		t.Fatal("Go verification", err)
	}

	contextSignature, err := key.Sign(rand.Reader, digest[:], &ed25519.Options{Hash: crypto.SHA512, Context: "different domain"})
	if err != nil {
		t.Fatal(err)
	}

	if err := xmldsig.VerifyMessage(t.Context(), message, contextSignature, public, xmldsig.Ed25519ph, policy); !errors.Is(err, xmldsig.ErrSignature) {
		t.Fatal("Ed25519ph accepted a nonempty EdDSA context", err)
	}

	// Pure Ed25519(SHA512(M)) has different domain separation from Ed25519ph(M).
	for _, signature := range [][]byte{ed25519.Sign(key, message), ed25519.Sign(key, digest[:])} {
		if err := xmldsig.VerifyMessage(t.Context(), message, signature, public, xmldsig.Ed25519ph, policy); !errors.Is(err, xmldsig.ErrSignature) {
			t.Fatal("wrong Ed25519 variant accepted", err)
		}
	}

	if err := xmldsig.VerifyMessage(t.Context(), message, want, public, xmldsig.Ed25519, policy); !errors.Is(err, xmldsig.ErrSignature) {
		t.Fatal("Ed25519ph accepted as pure Ed25519", err)
	}

	for _, message := range [][]byte{nil, {0, 0xff, 0xc0, '\r', '\n'}} {
		digest := sha512.Sum512(message)

		expected, err := key.Sign(rand.Reader, digest[:], &ed25519.Options{Hash: crypto.SHA512})
		if err != nil {
			t.Fatal(err)
		}

		value, err := xmldsig.SignMessageReader(t.Context(), bytes.NewReader(message), key, xmldsig.Ed25519ph, policy)
		if err != nil || !bytes.Equal(value, expected) {
			t.Fatal("Go signing of empty/binary input", err)
		}

		if err := xmldsig.VerifyMessageReader(t.Context(), iotest.DataErrReader(bytes.NewReader(message)), expected, public, xmldsig.Ed25519ph, policy); err != nil {
			t.Fatal("Go verification of empty/binary input", err)
		}
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "core", "ec256-enveloping-cm0.jdk.xml"))
	if err != nil {
		b.Fatal(err)
	}

	key := coreFixtureKey(b, "ec256.pub.pem")

	d, err := document.Parse(b.Context(), raw, document.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	selected := xmldsig.Signatures(d)[0]

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := xmldsig.VerifySignature(context.Background(), d, selected, key, xmldsig.SignatureOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHMACMessage(b *testing.B) {
	key := testMACKey()
	data := bytes.Repeat([]byte("x"), 1024)
	p := xmldsig.HMACPolicy()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, e := xmldsig.ComputeHMAC(context.Background(), data, key, xmldsig.HMACSHA256, 0, p); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkParameterizedPSSVerify(b *testing.B) {
	key := pssKey(b, 2048)
	data := bytes.Repeat([]byte("x"), 1024)
	p := xmldsig.ParameterizedPolicy()
	params := xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA256, SaltLength: 20}}

	value, e := xmldsig.SignMessageWithParameters(context.Background(), data, key, xmldsig.RSAPSS, params, p)
	if e != nil {
		b.Fatal(e)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if e := xmldsig.VerifyMessageWithParameters(context.Background(), data, value, &key.PublicKey, xmldsig.RSAPSS, params, p); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkVerifyECDSA(b *testing.B) {
	key := ecKey(b, elliptic.P256())
	signed := sign(b, key, parse(b, input), xmldsig.SignOptions{})
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := xmldsig.Verify(context.Background(), signed, key.Public(), xmldsig.VerifyOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

// controlledSigner confirms that signing goes through the interface, not a concrete private-key assertion.
type controlledSigner struct {
	crypto.Signer
	calls int
	fn    func()
}

func (s *controlledSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	s.calls++
	if s.fn != nil {
		s.fn()
	}

	return s.Signer.Sign(r, d, o)
}

type failingSigner struct {
	crypto.Signer
	err error
}

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, s.err }

type badSigner struct{ crypto.Signer }

func (s badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return []byte("not DER"), nil
}

type contextTestSigner struct {
	key      crypto.Signer
	received context.Context
	cancel   context.CancelFunc
}

func (s *contextTestSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *contextTestSigner) Sign(ctx context.Context, r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	s.received = ctx
	if s.cancel != nil {
		s.cancel()
	}

	return s.key.Sign(r, d, o)
}
