package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestHMACMessageMethods(t *testing.T) {
	ctx := context.Background()
	key := testMACKey()
	before := bytes.Clone(key)
	msg := []byte("exact binary\x00\xff")

	for _, tc := range []struct {
		method string
		hash   crypto.Hash
	}{{xmldsig.HMACSHA256, crypto.SHA256}, {xmldsig.HMACSHA384, crypto.SHA384}, {xmldsig.HMACSHA512, crypto.SHA512}} {
		for _, bits := range []int{0, tc.hash.Size() * 8, tc.hash.Size() * 4} {
			t.Run(fmt.Sprintf("%s/%d", tc.method, bits), func(t *testing.T) { testHMACMessageMethodsCase(t, &ctx, &msg, &key, &tc, &bits) })
		}

		for _, bits := range []int{-1, 1, 79, 80, 127, tc.hash.Size()*4 - 8, tc.hash.Size()*4 + 1, tc.hash.Size()*8 + 8} {
			p := xmldsig.HMACPolicy()

			p.AllowHMACTruncation = true
			if _, e := xmldsig.ComputeHMAC(ctx, msg, key, tc.method, bits, p); !errors.Is(e, xmldsig.ErrPolicy) {
				t.Fatalf("unsafe length %d accepted: %v", bits, e)
			}
		}
	}

	if !bytes.Equal(key, before) {
		t.Fatal("caller key changed or cleared")
	}

	if _, e := xmldsig.ComputeHMAC(ctx, msg, key[:31], xmldsig.HMACSHA256, 0, xmldsig.HMACPolicy()); !errors.Is(e, xmldsig.ErrKey) {
		t.Fatal("short key", e)
	}

	if _, e := xmldsig.ComputeHMAC(ctx, msg, key, xmldsig.HMACSHA256, 0, xmldsig.Policy{}); !errors.Is(e, xmldsig.ErrPolicy) {
		t.Fatal("default enables HMAC", e)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	if _, e := xmldsig.ComputeHMAC(cancelled, msg, key, xmldsig.HMACSHA256, 0, xmldsig.HMACPolicy()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func testHMACMessageMethodsCase(t *testing.T, ctx *context.Context, msg *[]byte, key *[]byte, tc *struct {
	method string
	hash   crypto.Hash
}, bits *int,
) {
	p := xmldsig.HMACPolicy()
	p.AllowHMACTruncation = true

	tag, e := xmldsig.ComputeHMAC((*ctx), (*msg), (*key), tc.method, (*bits), p)
	if e != nil {
		t.Fatal(e)
	}

	m := hmac.New(tc.hash.New, (*key))
	m.Write((*msg))

	expected := m.Sum(nil)
	if (*bits) != 0 {
		expected = expected[:(*bits)/8]
	}

	if !hmac.Equal(tag, expected) {
		t.Fatal("stdlib MAC mismatch")
	}

	if e = xmldsig.VerifyHMAC((*ctx), (*msg), tag, (*key), tc.method, (*bits), p); e != nil {
		t.Fatal(e)
	}

	for _, bad := range [][]byte{tag[1:], append(bytes.Clone(tag), 0), bytes.Repeat([]byte{0}, len(tag))} {
		if e = xmldsig.VerifyHMAC((*ctx), (*msg), bad, (*key), tc.method, (*bits), p); !errors.Is(e, xmldsig.ErrSignature) {
			t.Fatalf("bad tag accepted %v", e)
		}
	}

	if e = xmldsig.VerifyHMAC((*ctx), []byte("changed"), tag, (*key), tc.method, (*bits), p); !errors.Is(e, xmldsig.ErrSignature) {
		t.Fatal(e)
	}

	if (*bits) != 0 && (*bits) != tc.hash.Size()*8 {
		if _, e = xmldsig.ComputeHMAC((*ctx), (*msg), (*key), tc.method, (*bits), xmldsig.HMACPolicy()); !errors.Is(e, xmldsig.ErrPolicy) {
			t.Fatalf("implicit truncation %v", e)
		}
	}
}

func TestHMACTemplateChecksAllReferences(t *testing.T) {
	ctx := context.Background()
	key := testMACKey()

	for _, method := range []string{xmldsig.HMACSHA256, xmldsig.HMACSHA384, xmldsig.HMACSHA512} {
		t.Run(method, func(t *testing.T) {
			d, s := paramTemplate(t, method, xmldsig.SignatureParameters{})
			before := coreXML(t, d)
			o := xmldsig.SignatureOptions{Policy: xmldsig.HMACPolicy(), ExpectedURIs: []string{"#a", "#b"}, RequiredElements: []document.Element{coreFind(d, nameObject, "a")}}

			out, e := xmldsig.SignHMACTemplate(ctx, d, s, key, xmldsig.TemplateSignOptions{Validation: o})
			if e != nil {
				t.Fatal(e)
			}

			if before != coreXML(t, d) {
				t.Fatal("changed input")
			}

			serialized := coreXML(t, out)
			out = coreParse(t, serialized)
			o.RequiredElements = []document.Element{coreFind(out, nameObject, "a")}

			r, report, e := xmldsig.VerifyHMACSignatureDetailed(ctx, out, out.Root(), key, o)
			if e != nil || r == nil || report.Status != xmldsig.Valid || len(r.References()) != 2 || !r.CoversElement(o.RequiredElements[0]) || r.CoversElement(out.Root()) || r.CoversElement(coreFind(d, nameObject, "a")) {
				t.Fatalf("%v %+v", e, report)
			}

			if r.SignatureMethod() != method || r.OutputLength() < 256 || !r.Signature().Valid() {
				t.Fatal("HMAC result")
			}
			// Only payload b changes: SignedInfo/HMAC are untouched. Earlier valid
			// reference must not mask failure of the second Reference.
			bad := coreParse(t, strings.Replace(serialized, "payload-b", "corrupted-b", 1))
			o.RequiredElements = nil

			r, report, e = xmldsig.VerifyHMACSignatureDetailed(ctx, bad, bad.Root(), key, o)
			if r != nil || !errors.Is(e, xmldsig.ErrDigest) || report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid || report.References[1].Status != xmldsig.Invalid {
				t.Fatalf("bad second ref %v %+v", e, report)
			}

			wrong := bytes.Clone(key)

			wrong[0] ^= 1
			if r, _, e = xmldsig.VerifyHMACSignatureDetailed(ctx, out, out.Root(), wrong, o); r != nil || !errors.Is(e, xmldsig.ErrSignature) {
				t.Fatal("wrong secret", e)
			}
			// A []byte placed in crypto.PublicKey MUST NOT switch trust model.
			if pub, e := xmldsig.VerifySignature(ctx, out, out.Root(), key, o); pub != nil || !errors.Is(e, xmldsig.ErrKey) {
				t.Fatal("public key API accepted MAC", e)
			}

			if _, e = xmldsig.VerifySignatureWithKeyInfo(ctx, out, out.Root(), xmldsig.KeyInfoVerifyOptions{Signature: o, SelectTrustedKey: nil}); !errors.Is(e, xmldsig.ErrKeyInfoTrust) {
				t.Fatal(e)
			}
		})
	}
}

func TestHMACMalformedAndDisabledParameters(t *testing.T) {
	d, _ := paramTemplate(t, xmldsig.HMACSHA256, xmldsig.SignatureParameters{HMACOutputLength: 128})

	raw := coreXML(t, d)
	for _, value := range []string{"0", "-1", "1", "80", "127", "129", "257", "2560", "999999999999999999999", "12<!--comment-->8"} {
		t.Run(value, func(t *testing.T) {
			changed := strings.Replace(raw, ">128</ds:HMACOutputLength>", ">"+value+"</ds:HMACOutputLength>", 1)
			input := coreParse(t, changed)
			p := xmldsig.HMACPolicy()
			p.AllowHMACTruncation = true

			out, e := xmldsig.SignHMACTemplate(context.Background(), input, input.Root(), testMACKey(), xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: p}})
			if e == nil || out != nil {
				t.Fatal("bad XML parameter accepted")
			}
		})
	}

	duplicate := strings.Replace(raw, "</ds:SignatureMethod>", "<ds:HMACOutputLength>256</ds:HMACOutputLength></ds:SignatureMethod>", 1)

	input := coreParse(t, duplicate)
	if _, e := xmldsig.SignHMACTemplate(context.Background(), input, input.Root(), testMACKey(), xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: xmldsig.HMACPolicy()}}); e == nil {
		t.Fatal("duplicate parameter accepted")
	}
}

func TestHMACExternalAuthenticationGate(t *testing.T) {
	ctx := context.Background()
	key := testMACKey()
	calls, closed := 0, 0
	resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return &countClose{Reader: strings.NewReader("external payload"), n: &closed}, nil
	})

	d, s, e := xmldsig.BuildTemplate(ctx, nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.HMACSHA256, References: []xmldsig.ReferenceTemplate{{URI: uriUrnData}, {URI: uriUrnData}}})
	if e != nil {
		t.Fatal(e)
	}

	opt := xmldsig.SignatureOptions{Policy: xmldsig.HMACPolicy(), External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnData}, Resolver: resolver}}

	out, e := xmldsig.SignHMACTemplate(ctx, d, s, key, xmldsig.TemplateSignOptions{Validation: opt})
	if e != nil || calls != 1 || closed != 1 {
		t.Fatalf("generation replay %v calls=%d closed=%d", e, calls, closed)
	}

	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	calls = 0

	r, report, e := xmldsig.VerifyHMACSignatureDetailed(ctx, out, out.Root(), wrong, opt)
	if r != nil || !errors.Is(e, xmldsig.ErrSignature) || calls != 0 || report.References[0].Status != xmldsig.NotChecked {
		t.Fatalf("read before MAC %v calls=%d %+v", e, calls, report)
	}

	if _, e = xmldsig.VerifyHMACSignature(ctx, out, out.Root(), key, opt); e != nil || calls != 1 {
		t.Fatal("valid fetch", e, calls)
	}
}

func TestHMACPreservationAndManifests(t *testing.T) {
	ctx := context.Background()
	key := testMACKey()
	root := coreParse(t, `<root><item ID="data">value</item></root>`)
	template := xmldsig.SignatureTemplate{SignatureMethod: xmldsig.HMACSHA256, References: []xmldsig.ReferenceTemplate{{URI: nameData, Transforms: []reference.Transform{{Algorithm: c14n.Exclusive}}}}}

	d, s, e := xmldsig.BuildTemplate(ctx, root, root.Root(), template)
	if e != nil {
		t.Fatal(e)
	}

	opt := xmldsig.SignatureOptions{Policy: xmldsig.HMACPolicy()}

	signed, e := xmldsig.SignHMACTemplate(ctx, d, s, key, xmldsig.TemplateSignOptions{Validation: opt})
	if e != nil {
		t.Fatal(e)
	}

	template.SignatureMethod = xmldsig.RSAPSS

	d, s, e = xmldsig.BuildTemplate(ctx, signed, signed.Root(), template)
	if e != nil {
		t.Fatal(e)
	}

	req := xmldsig.SignatureRequirement{Signature: xmldsig.Signatures(d)[0], SharedSecret: key, Options: opt}
	newKey := pssKey(t, 2048)

	out, e := xmldsig.SignTemplate(ctx, d, s, newKey, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: xmldsig.ParameterizedPolicy()}, Preserve: []xmldsig.SignatureRequirement{req}})
	if e != nil {
		t.Fatal(e)
	}

	if _, e = xmldsig.VerifyHMACSignature(ctx, out, xmldsig.Signatures(out)[0], key, opt); e != nil {
		t.Fatal(e)
	}

	if _, e = xmldsig.VerifySignature(ctx, out, xmldsig.Signatures(out)[1], newKey.Public(), xmldsig.SignatureOptions{Policy: xmldsig.ParameterizedPolicy()}); e != nil {
		t.Fatal(e)
	}

	if !bytes.Equal(key, testMACKey()) {
		t.Fatal("preserve cleared caller secret")
	}

	graph, _ := makeGraph(t, false)
	xml := strings.Replace(coreXML(t, graph), xmldsig.ECDSASHA256, xmldsig.HMACSHA256, 1)
	graph = coreParse(t, xml)
	goOpt := graphOptions()
	goOpt.Policy = xmldsig.HMACPolicy()

	macGraph, e := xmldsig.SignHMACTemplate(ctx, graph, graph.Root(), key, xmldsig.TemplateSignOptions{Validation: goOpt})
	if e != nil {
		t.Fatal(e)
	}

	result, e := xmldsig.VerifyHMACSignature(ctx, macGraph, macGraph.Root(), key, goOpt)
	if e != nil || len(result.Manifests()) != 2 {
		t.Fatal(e)
	}
}

func TestHMACConcurrentReadOnlyVerification(t *testing.T) {
	key := testMACKey()
	d, s := paramTemplate(t, xmldsig.HMACSHA256, xmldsig.SignatureParameters{})
	o := xmldsig.SignatureOptions{Policy: xmldsig.HMACPolicy()}

	out, e := xmldsig.SignHMACTemplate(context.Background(), d, s, key, xmldsig.TemplateSignOptions{Validation: o})
	if e != nil {
		t.Fatal(e)
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, e := xmldsig.VerifyHMACSignature(context.Background(), out, out.Root(), key, o); e != nil {
				t.Error(e)
			}
		})
	}

	wg.Wait()
}

func TestHMACPreservationRefusesInvalidation(t *testing.T) {
	ctx := context.Background()
	key := testMACKey()
	d := coreParse(t, `<r ID="r">payload</r>`)
	spec := xmldsig.SignatureTemplate{SignatureMethod: xmldsig.HMACSHA256, References: []xmldsig.ReferenceTemplate{{URI: "#r", Transforms: []reference.Transform{{Algorithm: xmldsig.EnvelopedSignature}, {Algorithm: c14n.Exclusive}}}}}

	d, _, e := xmldsig.BuildTemplate(ctx, d, d.Root(), spec)
	if e != nil {
		t.Fatal(e)
	}
	// Install both empty templates before signing the first. Filling the second
	// modifies bytes covered by the first MAC and must abort preservation.
	d, _, e = xmldsig.BuildTemplate(ctx, d, d.Root(), spec)
	if e != nil {
		t.Fatal(e)
	}

	first := xmldsig.Signatures(d)[0]
	opt := xmldsig.SignatureOptions{Policy: xmldsig.HMACPolicy()}

	one, e := xmldsig.SignHMACTemplate(ctx, d, first, key, xmldsig.TemplateSignOptions{Validation: opt})
	if e != nil {
		t.Fatal(e)
	}

	before := coreXML(t, one)
	sigs := xmldsig.Signatures(one)

	out, e := xmldsig.SignHMACTemplate(ctx, one, sigs[1], key, xmldsig.TemplateSignOptions{Validation: opt, Preserve: []xmldsig.SignatureRequirement{{Signature: sigs[0], SharedSecret: key, Options: opt}}})
	if out != nil || e == nil {
		t.Fatal("invalidated MAC returned")
	}

	if before != coreXML(t, one) {
		t.Fatal("input modified despite failure")
	}
	// Both credential kinds in a preservation requirement must fail closed.
	out, e = xmldsig.SignHMACTemplate(ctx, one, sigs[1], key, xmldsig.TemplateSignOptions{Validation: opt, Preserve: []xmldsig.SignatureRequirement{{Signature: sigs[0], SharedSecret: key, PublicKey: graphKey(t).Public(), Options: opt}}})
	if out != nil || !errors.Is(e, xmldsig.ErrPolicy) {
		t.Fatalf("ambiguous preservation %v", e)
	}

	if !bytes.Equal(key, testMACKey()) {
		t.Fatal("caller secret wiped on error")
	}
}

func TestHMACRequiresExplicitCoverageAndTrustKind(t *testing.T) {
	ctx := context.Background()
	key := testMACKey()
	d, s := paramTemplate(t, xmldsig.HMACSHA256, xmldsig.SignatureParameters{})
	p := xmldsig.HMACPolicy()

	signed, e := xmldsig.SignHMACTemplate(ctx, d, s, key, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: p}})
	if e != nil {
		t.Fatal(e)
	}

	o := xmldsig.SignatureOptions{Policy: p, RequiredElements: []document.Element{signed.Root()}}

	r, report, e := xmldsig.VerifyHMACSignatureDetailed(ctx, signed, signed.Root(), key, o)
	if r != nil || !errors.Is(e, xmldsig.ErrPolicy) || report.FailureStage != "coverage" {
		t.Fatalf("root was trusted %v", e)
	}
	// Public-key URI passed to the symmetric API is not permitted even when a
	// caller manually adds that URI to an HMAC policy.
	p.AllowedSignatureMethods = append(p.AllowedSignatureMethods, xmldsig.ECDSASHA256)

	d, s = paramTemplate(t, xmldsig.ECDSASHA256, xmldsig.SignatureParameters{})
	if out, e := xmldsig.SignHMACTemplate(ctx, d, s, key, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: p}}); out != nil || !errors.Is(e, xmldsig.ErrKey) {
		t.Fatalf("trust-mode confusion %v", e)
	}
}

func TestHMACZeroResultAndTagCapacity(t *testing.T) {
	for _, r := range []*xmldsig.HMACResult{nil, {}} {
		if r.Signature().Valid() || r.SignatureMethod() != "" || r.OutputLength() != 0 || len(r.References()) != 0 || len(r.Manifests()) != 0 || r.CoversElement(document.Element{}) {
			t.Fatal("nonzero empty result")
		}
	}

	p := xmldsig.HMACPolicy()
	p.AllowHMACTruncation = true

	tag, e := xmldsig.ComputeHMAC(context.Background(), []byte("m"), testMACKey(), xmldsig.HMACSHA512, 256, p)
	if e != nil || len(tag) != 32 || cap(tag) != 32 {
		t.Fatalf("hidden full tag capacity len=%d cap=%d err=%v", len(tag), cap(tag), e)
	}
}

func testMACKey() []byte { return bytes.Repeat([]byte{0xa7}, 64) } // PUBLIC test data, not a production secret
