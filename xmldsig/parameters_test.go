package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestParameterizedPSSMessages(t *testing.T) {
	ctx := context.Background()
	key := pssKey(t, 2048)
	msg := []byte("message with exact bytes\x00\xff")
	policy := xmldsig.ParameterizedPolicy()

	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		for _, salt := range []int{1, 20, h.Size(), 80, 256 - h.Size() - 2} {
			t.Run(fmt.Sprintf("%v-salt%d", h, salt), func(t *testing.T) {
				p := xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: h, SaltLength: salt}}

				value, e := xmldsig.SignMessageWithParameters(ctx, msg, key, xmldsig.RSAPSS, p, policy)
				if e != nil {
					t.Fatal(e)
				}

				hash := h.New()
				hash.Write(msg)

				if e = rsa.VerifyPSS(&key.PublicKey, h, hash.Sum(nil), value, &rsa.PSSOptions{Hash: h, SaltLength: salt}); e != nil {
					t.Fatal("stdlib rejects generated signature", e)
				}

				other, e := rsa.SignPSS(rand.Reader, key, h, hash.Sum(nil), &rsa.PSSOptions{Hash: h, SaltLength: salt})
				if e != nil {
					t.Fatal(e)
				}

				if e = xmldsig.VerifyMessageWithParameters(ctx, msg, other, &key.PublicKey, xmldsig.RSAPSS, p, policy); e != nil {
					t.Fatal(e)
				}

				p.PSS.SaltLength++
				if e = xmldsig.VerifyMessageWithParameters(ctx, msg, value, &key.PublicKey, xmldsig.RSAPSS, p, policy); e == nil {
					t.Fatal("accepted wrong salt length")
				}
			})
		}
	}
	// Non-byte-aligned modulus: k=257 bytes but emLen=256. Verify both paths.
	odd := pssKey(t, 2049)

	value, e := xmldsig.SignMessageWithParameters(ctx, msg, odd, xmldsig.RSAPSS, xmldsig.SignatureParameters{}, policy)
	if e != nil {
		t.Fatal(e)
	}

	if e = xmldsig.VerifyMessageWithParameters(ctx, msg, value, &odd.PublicKey, xmldsig.RSAPSS, xmldsig.SignatureParameters{}, policy); e != nil {
		t.Fatal(e)
	}

	for _, bad := range [][]byte{value[1:], append(bytes.Clone(value), 0), bytes.Repeat([]byte{0xff}, len(value)), make([]byte, len(value))} {
		if e = xmldsig.VerifyMessageWithParameters(ctx, msg, bad, &odd.PublicKey, xmldsig.RSAPSS, xmldsig.SignatureParameters{}, policy); !errors.Is(e, xmldsig.ErrSignature) {
			t.Fatalf("bad encoding: %v", e)
		}
	}
}

func TestParameterizedProviderAndPreflight(t *testing.T) {
	ctx := context.Background()
	key := pssKey(t, 2048)
	provider := &pssProvider{PrivateKey: key}
	param := xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA384, SaltLength: 24}}

	value, e := xmldsig.SignMessageWithParameters(ctx, []byte("m"), provider, xmldsig.RSAPSS, param, xmldsig.ParameterizedPolicy())
	if e != nil || len(value) == 0 || provider.calls != 1 || provider.seen != ctx || provider.params.MGFHash != crypto.SHA384 || provider.params.TrailerField != 1 {
		t.Fatalf("provider %v %+v", e, provider)
	}

	provider.bad = true
	if value, e = xmldsig.SignMessageWithParameters(ctx, []byte("m"), provider, xmldsig.RSAPSS, param, xmldsig.ParameterizedPolicy()); value != nil || !errors.Is(e, xmldsig.ErrSignature) {
		t.Fatalf("bad provider accepted %v", e)
	}

	provider.bad = false

	provider.mutateDigest = true
	if value, err := xmldsig.SignMessageWithParametersReader(ctx, strings.NewReader("original"), provider, xmldsig.RSAPSS, param, xmldsig.ParameterizedPolicy()); value != nil || !errors.Is(err, xmldsig.ErrSignature) {
		t.Fatalf("mutating provider accepted: %v", err)
	}

	provider.mutateDigest = false

	provider.err = errors.New("provider-failure")
	if _, e = xmldsig.SignMessageWithParameters(ctx, []byte("m"), provider, xmldsig.RSAPSS, param, xmldsig.ParameterizedPolicy()); !errors.Is(e, provider.err) {
		t.Fatal(e)
	}

	provider.err = nil
	canceled, cancel := context.WithCancel(ctx)

	provider.cancel = cancel
	if value, e = xmldsig.SignMessageWithParameters(canceled, []byte("m"), provider, xmldsig.RSAPSS, param, xmldsig.ParameterizedPolicy()); value != nil || !errors.Is(e, context.Canceled) {
		t.Fatalf("canceled provider %v", e)
	}

	for _, p := range []xmldsig.PSSParameters{{Hash: crypto.SHA256, MGFHash: crypto.SHA384, SaltLength: 32}, {Hash: crypto.SHA256, SaltLength: 0}} {
		// Native crypto.Signer cannot express these. Reject BEFORE reading
		// any external payload, not after performing an expensive operation.
		d, s, e := xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.RSAPSS, SignatureParameters: xmldsig.SignatureParameters{PSS: &p}, References: []xmldsig.ReferenceTemplate{{URI: uriUrnData}}})
		if e != nil {
			t.Fatal(e)
		}

		reads := 0
		opt := xmldsig.SignatureOptions{Policy: xmldsig.ParameterizedPolicy(), External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnData}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			reads++
			return io.NopCloser(strings.NewReader(nameData2)), nil
		})}}

		out, e := xmldsig.SignTemplate(ctx, d, s, key, xmldsig.TemplateSignOptions{Validation: opt})
		if out != nil || !errors.Is(e, xmldsig.ErrAlgorithm) || reads != 0 {
			t.Fatalf("missing capability not preflighted %v reads=%d", e, reads)
		}
	}
}

func TestParameterizedPSSXML(t *testing.T) {
	ctx := context.Background()

	key := pssKey(t, 2048)
	for _, params := range []xmldsig.SignatureParameters{{}, {PSS: &xmldsig.PSSParameters{Hash: crypto.SHA384, SaltLength: 20}}, {PSS: &xmldsig.PSSParameters{Hash: crypto.SHA512, MGFHash: crypto.SHA512, SaltLength: 64}}} {
		d, s := paramTemplate(t, xmldsig.RSAPSS, params)
		before := coreXML(t, d)
		opt := xmldsig.SignatureOptions{Policy: xmldsig.ParameterizedPolicy(), RequiredElements: []document.Element{coreFind(d, nameObject, "a")}, ExpectedURIs: []string{"#a", "#b"}}

		signed, e := xmldsig.SignTemplate(ctx, d, s, key, xmldsig.TemplateSignOptions{Validation: opt})
		if e != nil {
			t.Fatal(e)
		}

		if before != coreXML(t, d) {
			t.Fatal("mutated original")
		}

		opt.RequiredElements = []document.Element{coreFind(signed, nameObject, "a")}

		r, report, e := xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), &key.PublicKey, opt)
		if e != nil {
			t.Fatal(e)
		}

		if report.Status != xmldsig.Valid || len(r.References()) != 2 || !r.CoversElement(opt.RequiredElements[0]) || r.CoversElement(signed.Root()) {
			t.Fatalf("bad result %+v", report)
		}

		p := r.Parameters()

		p.PSS.Hash = crypto.SHA1
		if r.Parameters().PSS.Hash == crypto.SHA1 {
			t.Fatal("mutable result parameters")
		}

		raw := coreXML(t, signed)
		modified := coreParse(t, strings.Replace(raw, "payload-b", "changed-b", 1))
		opt.RequiredElements = nil

		r, report, e = xmldsig.VerifySignatureDetailed(ctx, modified, modified.Root(), &key.PublicKey, opt)
		if r != nil || !errors.Is(e, xmldsig.ErrDigest) || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid || report.References[1].Status != xmldsig.Invalid {
			t.Fatalf("second digest bypass %v %+v", e, report)
		}

		if _, e = xmldsig.VerifySignature(ctx, signed, signed.Root(), &key.PublicKey, xmldsig.SignatureOptions{}); !errors.Is(e, xmldsig.ErrPolicy) {
			t.Fatalf("implicit opt-in %v", e)
		}
	}
}

func TestSignatureParameterXMLRejects(t *testing.T) {
	key := &countSigner{Signer: pssKey(t, 2048)}
	p := xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA256, SaltLength: 32, TrailerField: 1}}
	draft, _ := paramTemplate(t, xmldsig.RSAPSS, p)
	raw := coreXML(t, draft)

	cases := []struct {
		name string
		edit func(string) string
	}{
		{"duplicate salt", func(s string) string {
			return strings.Replace(s, "<pss:SaltLength>32</pss:SaltLength>", "<pss:SaltLength>32</pss:SaltLength><pss:SaltLength>32</pss:SaltLength>", 1)
		}},
		{"zero trailer", func(s string) string {
			return strings.Replace(s, "<pss:TrailerField>1</pss:TrailerField>", "<pss:TrailerField>0</pss:TrailerField>", 1)
		}},
		{"negative salt", func(s string) string { return strings.Replace(s, ">32</pss:SaltLength>", ">-1</pss:SaltLength>", 1) }},
		{"huge integer", func(s string) string {
			return strings.Replace(s, ">32</pss:SaltLength>", ">999999999999999999999999</pss:SaltLength>", 1)
		}},
		{"oversized salt", func(s string) string { return strings.Replace(s, ">32</pss:SaltLength>", ">230</pss:SaltLength>", 1) }},
		{"parameter splice", func(s string) string {
			return strings.Replace(s, ">32</pss:SaltLength>", ">3<!--split-->2</pss:SaltLength>", 1)
		}},
		{"wrong namespace", func(s string) string { return strings.ReplaceAll(s, "pss:SaltLength", "ds:SaltLength") }},
		{"MGF algorithm", func(s string) string { return strings.Replace(s, xmldsig.MGF1, "urn:unknown:mgf", 1) }},
		{"SHA1", func(s string) string { return strings.Replace(s, xmldsig.SHA256, xmldsig.Namespace+"sha1", 1) }},
		{"fixed method parameters", func(s string) string {
			return strings.Replace(s, `Algorithm="`+xmldsig.RSAPSS+`"`, `Algorithm="`+xmldsig.RSAPSSSHA256+`"`, 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := tc.edit(raw)
			if changed == raw {
				t.Fatal("test mutation did not apply")
			}

			d := coreParse(t, changed)
			before := key.calls

			out, e := xmldsig.SignTemplate(context.Background(), d, d.Root(), key, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: xmldsig.ParameterizedPolicy()}})
			if out != nil || e == nil || key.calls != before {
				t.Fatalf("invalid parameter accepted or reached provider %v", e)
			}
		})
	}

	for _, p := range []xmldsig.SignatureParameters{{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA1, SaltLength: 20}}, {PSS: &xmldsig.PSSParameters{Hash: crypto.SHA256, SaltLength: -1}}, {HMACOutputLength: 256}} {
		_, _, e := xmldsig.BuildTemplate(context.Background(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.RSAPSS, SignatureParameters: p, References: []xmldsig.ReferenceTemplate{{URI: "#a"}}})
		if e == nil {
			t.Fatal("builder accepted inappropriate parameters")
		}
	}
}

func TestParameterizedContextAdapter(t *testing.T) {
	ctx := context.Background()
	base := &pssProvider{PrivateKey: pssKey(t, 2048)}
	provider := &contextPSSProvider{base}

	adapted, e := xmldsig.AdaptContextSigner(provider)
	if e != nil {
		t.Fatal(e)
	}

	params := xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA512, SaltLength: 16}}

	value, e := xmldsig.SignMessageWithParameters(ctx, []byte("external context"), adapted, xmldsig.RSAPSS, params, xmldsig.ParameterizedPolicy())
	if e != nil || value == nil || base.calls != 1 || base.seen != ctx {
		t.Fatalf("capability lost %v", e)
	}

	plain, e := xmldsig.AdaptContextSigner(&contextTestSigner{key: base.PrivateKey})
	if e != nil {
		t.Fatal(e)
	}

	if _, ok := plain.(xmldsig.ParameterizedPSSSigner); ok {
		t.Fatal("adapter invents a capability")
	}
}

func TestPSSPolicyAndLegacyIsolation(t *testing.T) {
	ctx := context.Background()
	key := pssKey(t, 2048)
	msg := []byte("m")
	params := xmldsig.SignatureParameters{PSS: &xmldsig.PSSParameters{Hash: crypto.SHA384, SaltLength: 20}}
	p := xmldsig.ParameterizedPolicy()

	p.AllowedDigestMethods = []string{xmldsig.SHA256}
	if _, e := xmldsig.SignMessageWithParameters(ctx, msg, key, xmldsig.RSAPSS, params, p); !errors.Is(e, xmldsig.ErrPolicy) {
		t.Fatal(e)
	}

	p = xmldsig.ParameterizedPolicy()

	p.MinPSSSaltBytes = 24
	if _, e := xmldsig.SignMessageWithParameters(ctx, msg, key, xmldsig.RSAPSS, params, p); !errors.Is(e, xmldsig.ErrPolicy) {
		t.Fatal(e)
	}

	if _, e := xmldsig.SignMessage(ctx, msg, key, xmldsig.RSAPSS, xmldsig.ParameterizedPolicy()); !errors.Is(e, xmldsig.ErrAlgorithm) {
		t.Fatalf("old API ignores PSS parameters %v", e)
	}

	if _, e := xmldsig.SignMessage(ctx, msg, key, xmldsig.HMACSHA256, xmldsig.HMACPolicy()); !errors.Is(e, xmldsig.ErrAlgorithm) {
		t.Fatalf("old API uses RSA for HMAC %v", e)
	}

	doc := coreParse(t, `<r ID="r">x</r>`)
	if out, e := xmldsig.SignEnveloped(ctx, doc, key, xmldsig.SignOptions{SignatureMethod: xmldsig.RSAPSS, Policy: xmldsig.ParameterizedPolicy()}); out != nil || !errors.Is(e, xmldsig.ErrAlgorithm) {
		t.Fatalf("legacy root profile silently widened %v", e)
	}
}

func FuzzVerifyParameters(f *testing.F) {
	dir := filepath.Join("..", "testdata", "parameters")

	pubBytes, e := os.ReadFile(filepath.Join(dir, "rsa.spki.der"))
	if e != nil {
		f.Fatal(e)
	}

	pub, e := x509.ParsePKIXPublicKey(pubBytes)
	if e != nil {
		f.Fatal(e)
	}

	testKey := testMACKey()

	for _, name := range []string{"pss-256-mgf384-salt0.xml", "pss-default.xml", "pss-512-mgf256-salt20.wrong-salt.xml", "hmac-384-bits192.xml", "hmac-512-bits0.bad-digest.xml"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			f.Fatal(e)
		}

		f.Add(b)
	}

	f.Add([]byte(`<ds:Signature xmlns:ds="` + xmldsig.Namespace + `"/>`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}

		lim := document.DefaultLimits()
		lim.MaxBytes = 64 << 10
		lim.MaxNodes = 2048
		lim.MaxDepth = 32

		d, e := document.Parse(context.Background(), raw, lim)
		if e != nil {
			return
		}

		p := xmldsig.ParameterizedPolicy()
		p.MaxCanonicalBytes = 256 << 10

		p.MaxReferences = 4
		if r, _, e := xmldsig.VerifySignatureDetailed(context.Background(), d, d.Root(), pub, xmldsig.SignatureOptions{Policy: p}); (r != nil) != (e == nil) {
			t.Fatal("partial public-key result")
		}

		p = xmldsig.HMACPolicy()
		p.AllowHMACTruncation = true
		p.MaxCanonicalBytes = 256 << 10

		p.MaxReferences = 4
		if r, _, e := xmldsig.VerifyHMACSignatureDetailed(context.Background(), d, d.Root(), testKey, xmldsig.SignatureOptions{Policy: p}); (r != nil) != (e == nil) {
			t.Fatal("partial HMAC result")
		}
	})
}

func FuzzHMACMessage(f *testing.F) {
	f.Add([]byte("abc"), 128, uint8(0))
	f.Add([]byte{}, 192, uint8(1))
	f.Add([]byte("binary\xff"), 0, uint8(2))
	f.Add([]byte("x"), -1, uint8(1))
	f.Fuzz(func(t *testing.T, msg []byte, bits int, selector uint8) {
		if len(msg) > 64<<10 {
			return
		}

		methods := []string{xmldsig.HMACSHA256, xmldsig.HMACSHA384, xmldsig.HMACSHA512}
		p := xmldsig.HMACPolicy()
		p.AllowHMACTruncation = true

		tag, e := xmldsig.ComputeHMAC(context.Background(), msg, testMACKey(), methods[int(selector)%3], bits, p)
		if e != nil {
			if tag != nil {
				t.Fatal("partial tag")
			}

			return
		}

		if e = xmldsig.VerifyHMAC(context.Background(), msg, tag, testMACKey(), methods[int(selector)%3], bits, p); e != nil {
			t.Fatal(e)
		}

		tag[0] ^= 1
		if e = xmldsig.VerifyHMAC(context.Background(), msg, tag, testMACKey(), methods[int(selector)%3], bits, p); e == nil {
			t.Fatal("modified tag accepted")
		}
	})
}

func pssKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()

	k, e := rsa.GenerateKey(rand.Reader, bits)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

type pssProvider struct {
	*rsa.PrivateKey
	calls        int
	seen         context.Context
	params       xmldsig.PSSParameters
	bad          bool
	cancel       context.CancelFunc
	err          error
	mutateDigest bool
}

func (s *pssProvider) SignPSS(ctx context.Context, r io.Reader, d []byte, p xmldsig.PSSParameters) ([]byte, error) {
	s.calls++
	s.seen = ctx

	s.params = p
	if s.cancel != nil {
		s.cancel()
	}

	if s.err != nil {
		return nil, s.err
	}

	if s.bad {
		return make([]byte, s.Size()), nil
	}

	if s.mutateDigest {
		d[0] ^= 1
	}

	return rsa.SignPSS(r, s.PrivateKey, p.Hash, d, &rsa.PSSOptions{Hash: p.Hash, SaltLength: p.SaltLength})
}

func paramTemplate(t testing.TB, method string, params xmldsig.SignatureParameters) (*document.Document, document.Element) {
	t.Helper()

	a, b := "payload-a", "payload-b"

	d, s, e := xmldsig.BuildTemplate(context.Background(), nil, document.Element{}, xmldsig.SignatureTemplate{ID: "s", SignatureMethod: method, SignatureParameters: params, References: []xmldsig.ReferenceTemplate{{URI: "#a", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}, {URI: "#b", Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}, Objects: []xmldsig.ObjectTemplate{{ID: "a", Text: &a}, {ID: "b", Text: &b}}})
	if e != nil {
		t.Fatal(e)
	}

	return d, s
}

type contextPSSProvider struct{ *pssProvider }

func (s *contextPSSProvider) Sign(ctx context.Context, r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return s.pssProvider.Sign(r, d, o)
}
