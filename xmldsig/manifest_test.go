package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

func TestManifestGraphAndMixedReferences(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(strconv.FormatBool(external), func(t *testing.T) { testManifestGraphAndMixedReferencesCase(t, &external) })
	}
}

func testManifestGraphAndMixedReferencesCase(t *testing.T, external *bool) {
	ctx := context.Background()
	k := graphKey(t)
	d, s := makeGraph(t, (*external))
	before, _ := d.XML(ctx)
	opt := graphOptions()
	calls := 0
	closed := 0

	if *external {
		opt.External = &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnAttachment}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			calls++
			return &countClose{Reader: bytes.NewBufferString("external bytes"), n: &closed}, nil
		})}
	}

	out, e := xmldsig.SignTemplate(ctx, d, s, k, xmldsig.TemplateSignOptions{Validation: opt})
	if e != nil {
		t.Fatal(e)
	}

	if (*external) && (calls != 1 || closed != 1) {
		t.Fatalf("generation + selfcheck fetches=%d closes=%d", calls, closed)
	}

	after, _ := d.XML(ctx)
	if !bytes.Equal(before, after) {
		t.Fatal("input changed")
	}

	result, report, e := xmldsig.VerifySignatureDetailed(ctx, out, out.Root(), k.Public(), opt)
	if e != nil {
		t.Fatal(e)
	}

	if len(result.Manifests()) != 2 || report.ManifestValidation != xmldsig.Valid {
		t.Fatalf("report: %+v", report)
	}

	if len(result.Manifests()[0].References()) != 2 {
		t.Fatal("duplicate incoming Manifest references lost")
	}

	payload := result.Manifests()[1].References()[0].Target()
	if !result.CoversElement(payload) {
		t.Fatal("nested payload not covered")
	}

	refs := result.Manifests()[1].References()
	refs[0] = xmldsig.ReferenceResult{}

	if !result.CoversElement(payload) {
		t.Fatal("mutable result")
	}

	if (*external) && calls != 2 {
		t.Fatalf("shared Manifest fetched twice: %d", calls)
	}
}

func TestManifestDisabledAndBadNestedDigest(t *testing.T) {
	ctx := context.Background()
	k := graphKey(t)
	d, _ := makeGraph(t, false)
	raw, _ := d.XML(ctx)
	// Fill nested digest placeholders with deliberately wrong values, then sign
	// the Manifest itself using core-only mode. SignatureValue remains correct.
	marker := []byte("<ds:Manifest")
	pos := bytes.Index(raw, marker)
	head, tail := raw[:pos], raw[pos:]
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tail = bytes.ReplaceAll(tail, []byte("<ds:DigestValue></ds:DigestValue>"), []byte("<ds:DigestValue>"+zero+"</ds:DigestValue>"))
	prepared := graphDoc(t, string(append(append([]byte{}, head...), tail...)))

	signed, e := xmldsig.SignTemplate(ctx, prepared, prepared.Root(), k, xmldsig.TemplateSignOptions{})
	if e != nil {
		t.Fatal(e)
	}

	r, report, e := xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), xmldsig.SignatureOptions{})
	if e != nil || r == nil || report.ManifestValidation != xmldsig.NotChecked || len(r.Manifests()) != 0 {
		t.Fatalf("core mode: %v %+v", e, report)
	}

	r, report, e = xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), graphOptions())

	var me *xmldsig.ManifestReferenceError
	if r != nil || !errors.Is(e, xmldsig.ErrDigest) || !errors.As(e, &me) {
		t.Fatalf("nested mismatch not diagnosed: %v", e)
	}

	if report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid || report.Manifests[0].References[0].Status != xmldsig.Invalid || report.Manifests[0].References[1].Status != xmldsig.NotChecked {
		t.Fatalf("report: %+v", report)
	}
}

func TestManifestPolicyAndCycles(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(*xmldsig.SignatureOptions)
		mutate func(string) string
	}{
		{name: "depth", edit: func(o *xmldsig.SignatureOptions) { o.Manifests.MaxDepth = 1 }},
		{name: "nodes", edit: func(o *xmldsig.SignatureOptions) { o.Manifests.MaxManifests = 1 }},
		{name: "references", edit: func(o *xmldsig.SignatureOptions) { o.Manifests.MaxReferences = 3 }},
		{name: "cycle", mutate: func(s string) string { return strings.ReplaceAll(s, `URI="#a"`, `URI="#top"`) }},
		{name: "wrong type target", mutate: func(s string) string { return strings.Replace(s, `URI="#top"`, `URI="#a"`, 1) }},
		{name: "external disabled", mutate: func(s string) string { return strings.ReplaceAll(s, `URI="#a"`, `URI="urn:unlisted"`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, s := makeGraph(t, false)

			o := graphOptions()
			if tc.edit != nil {
				tc.edit(&o)
			}

			if tc.mutate != nil {
				raw, _ := d.XML(t.Context())
				d = graphDoc(t, tc.mutate(string(raw)))
				s = d.Root()
			}

			k := &countSigner{Signer: graphKey(t)}

			out, e := xmldsig.SignTemplate(context.Background(), d, s, k, xmldsig.TemplateSignOptions{Validation: o})
			if e == nil || out != nil || k.calls != 0 {
				t.Fatalf("not rejected before signing: %v calls=%d", e, k.calls)
			}
		})
	}
}

func TestMixedAuthBeforeIOAndBudgets(t *testing.T) {
	ctx := context.Background()
	k := graphKey(t)
	d, s := makeGraph(t, true)
	calls := 0
	o := graphOptions()
	o.External = &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnAttachment}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(strings.NewReader("bytes")), nil
	})}

	signed, e := xmldsig.SignTemplate(ctx, d, s, k, xmldsig.TemplateSignOptions{Validation: o})
	if e != nil {
		t.Fatal(e)
	}

	calls = 0
	wrong := graphKey(t)

	r, _, e := xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), wrong.Public(), o)
	if r != nil || e == nil || calls != 0 {
		t.Fatal("resolver invoked before authentication")
	}

	o.External.Limits.MaxResourceBytes = 2

	r, _, e = xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), o)
	if r != nil || e == nil {
		t.Fatal("resource budget bypassed")
	}

	o.External.Limits = xmldsig.ResourceLimits{}

	o.Policy.MaxCanonicalBytes = 200
	if r, _, e = xmldsig.VerifySignatureDetailed(ctx, signed, signed.Root(), k.Public(), o); r != nil || e == nil {
		t.Fatal("processing budget bypassed")
	}
}

func TestBuilderAppendAndDuplicateIDs(t *testing.T) {
	ctx := context.Background()
	d := graphDoc(t, `<r ID="r"><data ID="data">v</data></r>`)
	raw, _ := d.XML(ctx)
	spec := xmldsig.SignatureTemplate{ID: "s", SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: nameData, Transforms: graphC14N()}}}

	draft, s, e := xmldsig.BuildTemplate(ctx, d, d.Root(), spec)
	if e != nil {
		t.Fatal(e)
	}

	after, _ := d.XML(ctx)
	if !bytes.Equal(raw, after) || len(xmldsig.Signatures(draft)) != 1 {
		t.Fatal("builder mutated source")
	}

	if _, e = xmldsig.SignTemplate(ctx, draft, s, graphKey(t), xmldsig.TemplateSignOptions{}); e != nil {
		t.Fatal(e)
	}

	spec.ID = "r"
	if _, _, e = xmldsig.BuildTemplate(ctx, d, d.Root(), spec); e == nil {
		t.Fatal("duplicate ID allowed")
	}
}

func FuzzVerifyManifest(f *testing.F) {
	b, e := os.ReadFile("../testdata/next/ec256.python.xml")
	if e != nil {
		f.Fatal(e)
	}

	p, e := os.ReadFile("../testdata/next/ec256.pub.pem")
	if e != nil {
		f.Fatal(e)
	}

	block, _ := pem.Decode(p)

	public, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		f.Fatal(e)
	}

	payload, e := os.ReadFile("../testdata/next/attachment.bin")
	if e != nil {
		f.Fatal(e)
	}

	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			return
		}

		d, e := document.Parse(t.Context(), b, document.DefaultLimits())
		if e != nil {
			return
		}

		s := xmldsig.Signatures(d)
		if len(s) != 1 {
			return
		}

		_, _, _ = xmldsig.VerifySignatureDetailed(context.Background(), d, s[0], public, xmldsig.SignatureOptions{Policy: xmldsig.ModernPolicy(), Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive, MaxDepth: 4, MaxManifests: 8, MaxReferences: 32}, External: &xmldsig.ExternalReferences{AllowedURIs: []string{uriUrnAttachment}, Resolver: xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		})}})
	})
}

func graphKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func graphDoc(t *testing.T, raw string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(raw), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func graphC14N() []reference.Transform { return []reference.Transform{{Algorithm: c14n.Exclusive}} }

func makeGraph(t *testing.T, ext bool) (*document.Document, document.Element) {
	t.Helper()

	a := "payload"
	b := "second"

	leaves := []xmldsig.ReferenceTemplate{{URI: "#a", Transforms: graphC14N()}, {URI: "#b", Transforms: graphC14N()}}
	if ext {
		leaves = append(leaves, xmldsig.ReferenceTemplate{URI: uriUrnAttachment})
	}

	spec := xmldsig.SignatureTemplate{
		ID: "sig", SignatureMethod: xmldsig.ECDSASHA256,
		References: []xmldsig.ReferenceTemplate{{URI: "#top", Type: xmldsig.ManifestType, Transforms: graphC14N()}},
		Objects: []xmldsig.ObjectTemplate{
			{Manifest: &xmldsig.ManifestTemplate{ID: "top", References: []xmldsig.ReferenceTemplate{{URI: "#leaf", Type: xmldsig.ManifestType, Transforms: graphC14N()}, {URI: "#leaf", Transforms: graphC14N()}}}},
			{Manifest: &xmldsig.ManifestTemplate{ID: "leaf", References: leaves}},
			{ID: "a", Text: &a},
			{ID: "b", Text: &b},
		},
	}

	d, s, e := xmldsig.BuildTemplate(context.Background(), nil, document.Element{}, spec)
	if e != nil {
		t.Fatal(e)
	}

	return d, s
}

func graphOptions() xmldsig.SignatureOptions {
	return xmldsig.SignatureOptions{Manifests: xmldsig.ManifestPolicy{Mode: xmldsig.ManifestRecursive}, ExpectedURIs: []string{"#top"}}
}

type countClose struct {
	io.Reader
	n *int
}

func (c *countClose) Close() error { *c.n++; return nil }

type countSigner struct {
	crypto.Signer
	calls int
}

func (s *countSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(r, d, o)
}
