package protocol_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	idp      = "https://idp.example.test/metadata"
	sp       = "https://sp.example.test/metadata"
	acs      = "https://sp.example.test/acs"
	sso      = "https://idp.example.test/sso"
	password = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
)

const nameRequest = "_request"

func TestResponse(t *testing.T) {
	c := testcert.New(t)
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}

	d, e := protocol.SignResponse(context.Background(), responseSpec(), key)
	if e != nil {
		t.Fatal(e)
	}

	raw, e := d.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	d, e = document.Parse(t.Context(), raw, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	r, e := protocol.VerifyResponse(context.Background(), d, []crypto.PublicKey{c.LeafKey.Public()}, options())
	if e != nil {
		t.Fatal(e)
	}

	if r.NameID() != "alice" || r.AssertionID() != "_assertion" || !r.ResponseAuthenticated() || r.InResponseTo() != nameRequest || len(r.Attributes()) != 2 {
		t.Fatal("result")
	}

	a := r.Attributes()

	a[0].Values[0] = "evil"
	if r.Attributes()[0].Values[0] != "alice@example.test" {
		t.Fatal("mutable attributes")
	}

	for _, tc := range []struct {
		name string
		opts protocol.ResponseOptions
		keys []crypto.PublicKey
	}{{"wrong audience", func() protocol.ResponseOptions { o := options(); o.Audience = "https://other.test"; return o }(), []crypto.PublicKey{c.LeafKey.Public()}}, {"wrong request", func() protocol.ResponseOptions { o := options(); o.ExpectedRequestID = "_other"; return o }(), []crypto.PublicKey{c.LeafKey.Public()}}, {"wrong ACS", func() protocol.ResponseOptions { o := options(); o.Destination = "https://evil.test/"; return o }(), []crypto.PublicKey{c.LeafKey.Public()}}, {"expired", func() protocol.ResponseOptions { o := options(); o.At = testcert.Now().Add(4 * time.Minute); return o }(), []crypto.PublicKey{c.LeafKey.Public()}}, {"wrong context", func() protocol.ResponseOptions {
		o := options()
		o.ExpectedAuthnContexts = []string{"urn:stronger"}

		return o
	}(), []crypto.PublicKey{c.LeafKey.Public()}}, {"forced reauth", func() protocol.ResponseOptions {
		o := options()
		o.ForceAuthn = true
		o.RequestIssueInstant = testcert.Now()

		return o
	}(), []crypto.PublicKey{c.LeafKey.Public()}}, {"wrong key", options(), []crypto.PublicKey{c.TSAKey.Public()}}} {
		t.Run(tc.name, func(t *testing.T) {
			if r, e := protocol.VerifyResponse(context.Background(), d, tc.keys, tc.opts); r != nil || e == nil {
				t.Fatal("accepted")
			}
		})
	}

	changed, e := document.Parse(t.Context(), bytes.Replace(raw, []byte("alice"), []byte("mallory"), 1), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	if r, e := protocol.VerifyResponse(context.Background(), changed, []crypto.PublicKey{c.LeafKey.Public()}, options()); r != nil || e == nil {
		t.Fatal("tamper accepted")
	}
	// Compatibility option never relaxes the signed Assertion requirement.
	unsigned := removeSignatures(t, d, false)
	if _, e := protocol.VerifyResponse(context.Background(), unsigned, []crypto.PublicKey{c.LeafKey.Public()}, options()); e == nil {
		t.Fatal("unsigned envelope accepted by default")
	}

	o := options()

	o.AllowUnsignedResponse = true
	if r, e := protocol.VerifyResponse(context.Background(), unsigned, []crypto.PublicKey{c.LeafKey.Public()}, o); e != nil || r == nil || r.ResponseAuthenticated() {
		t.Fatalf("compatibility %v", e)
	}
}

func TestCryptographicallyValidSemanticFailures(t *testing.T) {
	c := testcert.New(t)

	d, e := protocol.SignResponse(context.Background(), responseSpec(), protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if e != nil {
		t.Fatal(e)
	}

	tests := []struct {
		name   string
		change func(*tree.Node)
	}{
		{"invalid dateTime comma", func(n *tree.Node) {
			set(find(n, "Assertion"), "IssueInstant", testcert.Now().Format("2006-01-02T15:04:05")+",0Z")
		}},
		{"signed wrong audience", func(n *tree.Node) { find(n, "Audience").Children[0].Data = "https://evil.test" }},
		{"signed other recipient", func(n *tree.Node) { set(find(n, "SubjectConfirmationData"), "Recipient", "https://evil.test") }},
		{"signed wrong confirmation request", func(n *tree.Node) { set(find(n, "SubjectConfirmationData"), "InResponseTo", "_other") }},
		{"forbidden bearer NotBefore", func(n *tree.Node) {
			set(find(n, "SubjectConfirmationData"), "NotBefore", xmlutil.Time(testcert.Now().Add(-time.Minute)))
		}},
		{"unknown confirmation method", func(n *tree.Node) { set(find(n, "SubjectConfirmation"), "Method", "urn:unsupported") }},
		{"address without trusted client input", func(n *tree.Node) { set(find(n, "SubjectConfirmationData"), "Address", "192.0.2.1") }},
		{"expired confirmation", func(n *tree.Node) {
			set(find(n, "SubjectConfirmationData"), "NotOnOrAfter", xmlutil.Time(testcert.Now()))
		}},
		{"future conditions", func(n *tree.Node) {
			set(find(n, "Conditions"), "NotBefore", xmlutil.Time(testcert.Now().Add(time.Minute)))
		}},
		{"bad qualifier", func(n *tree.Node) { set(find(n, "NameID"), "NameQualifier", "https://other.test") }},
		{"duplicate attribute", func(n *tree.Node) {
			a := find(n, "AttributeStatement")
			child := *a.Children[0]
			child.Parent = a
			a.Children = append(a.Children, &child)
		}},
		{"nil attribute value", func(n *tree.Node) {
			v := find(n, "AttributeValue")
			v.NS = append(v.NS, tree.Namespace{Prefix: "xsi", URI: "http://www.w3.org/2001/XMLSchema-instance"})
			v.Attrs = append(v.Attrs, tree.Attribute{Name: document.Name{Space: "http://www.w3.org/2001/XMLSchema-instance", Local: "nil"}, Prefix: "xsi", Value: "true"})
		}},
		{"AND audience restriction", func(n *tree.Node) {
			conditions := find(n, "Conditions")
			ar := xmlutil.Node("saml", protocol.AssertionNamespace, "AudienceRestriction")
			a := xmlutil.Node("saml", protocol.AssertionNamespace, "Audience")
			xmlutil.Text(a, "https://other.test")
			xmlutil.Add(ar, a)
			xmlutil.Add(conditions, ar)
		}},
		{"unknown condition", func(n *tree.Node) {
			xmlutil.Add(find(n, "Conditions"), xmlutil.Node("saml", protocol.AssertionNamespace, "ProxyRestriction"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bad := resign(t, d, c, tc.change)
			for _, s := range xmldsig.Signatures(bad) {
				if _, e := xmldsig.VerifySignature(context.Background(), bad, s, c.LeafKey.Public(), xmldsig.SignatureOptions{}); e != nil {
					t.Fatal("negative control NOT cryptographically valid", e)
				}
			}

			if r, e := protocol.VerifyResponse(context.Background(), bad, []crypto.PublicKey{c.LeafKey.Public()}, options()); r != nil || e == nil {
				t.Fatal("accepted signed semantic error")
			}
		})
	}
}

func resign(t *testing.T, d *document.Document, c testcert.Chain, mutate func(*tree.Node)) *document.Document {
	t.Helper()
	d = removeSignatures(t, d, true)

	snapshot, cloneErr := tree.Clone(t.Context(), d)
	if cloneErr != nil {
		t.Fatal(cloneErr)
	}

	mutate(tree.Root(snapshot))

	b, e := snapshot.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	snapshot, e = document.Parse(t.Context(), b, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	a, e := xmlutil.Direct(snapshot.Root(), xmlutil.Name(protocol.AssertionNamespace, "Assertion"))
	if e != nil {
		t.Fatal(e)
	}

	k := xmlsig.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Method: xmldsig.ECDSASHA256}

	snapshot, e = xmlsig.Sign(context.Background(), snapshot, a, k, true)
	if e != nil {
		t.Fatal(e)
	}

	snapshot, e = xmlsig.Sign(context.Background(), snapshot, snapshot.Root(), k, true)
	if e != nil {
		t.Fatal(e)
	}

	return snapshot
}

func find(n *tree.Node, local string) *tree.Node {
	if n.Kind == tree.ElementNode && n.Name.Local == local {
		return n
	}

	for _, c := range n.Children {
		if r := find(c, local); r != nil {
			return r
		}
	}

	return nil
}

func set(n *tree.Node, name, value string) {
	for i := range n.Attrs {
		if n.Attrs[i].Name == (document.Name{Local: name}) {
			n.Attrs[i].Value = value
			return
		}
	}

	n.Attrs = append(n.Attrs, tree.Attribute{Name: document.Name{Local: name}, Value: value})
}

func TestAuthnRequest(t *testing.T) {
	c := testcert.New(t)
	spec := protocol.AuthnRequest{ID: nameRequest, Issuer: sp, Destination: sso, ACS: acs, IssueInstant: testcert.Now(), NameIDFormat: protocol.NameIDPersistent, AllowCreateNameID: true, RequestedContexts: []string{password}}
	key := protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw}

	d, e := protocol.SignAuthnRequest(context.Background(), spec, key)
	if e != nil {
		t.Fatal(e)
	}

	o := protocol.RequestOptions{Issuer: sp, Destination: sso, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: acs, Index: 0, Indexed: true, Default: true}}, At: testcert.Now()}

	r, e := protocol.VerifyAuthnRequest(context.Background(), d, []crypto.PublicKey{c.TSAKey.Public(), c.LeafKey.Public()}, o)
	if e != nil || r.ACS() != acs || r.ID() != nameRequest {
		t.Fatal(e)
	}

	r.RequestedContexts()[0] = "bad"
	if r.RequestedContexts()[0] != password {
		t.Fatal("mutable")
	}

	relay := "opaque"

	query, e := binding.SignRedirect(context.Background(), d, binding.Request, &relay, c.LeafKey, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
	if e != nil {
		t.Fatal(e)
	}

	rr, e := protocol.VerifyRedirectRequest(context.Background(), query, []crypto.PublicKey{c.LeafKey.Public()}, o, binding.Options{})
	if e != nil {
		t.Fatal(e)
	}

	if s, ok := rr.RelayState(); !ok || s != relay {
		t.Fatal("relay")
	}

	if _, e = protocol.VerifyRedirectRequest(context.Background(), strings.Replace(query, "RelayState=opaque", "RelayState=evil", 1), []crypto.PublicKey{c.LeafKey.Public()}, o, binding.Options{}); e == nil {
		t.Fatal("binding tamper")
	}

	o.ACS = []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: "https://evil.test/acs", Index: 0}}
	if _, e = protocol.VerifyAuthnRequest(context.Background(), d, []crypto.PublicKey{c.LeafKey.Public()}, o); e == nil {
		t.Fatal("unlisted ACS")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, e = protocol.VerifyAuthnRequest(ctx, d, []crypto.PublicKey{c.LeafKey.Public()}, o); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func FuzzVerifyResponse(f *testing.F) {
	fixture := testcert.LoadFixture(f, "../../testdata/saml-interop", "ecdsa-response-valid")
	b := fixture.Read(f, "ecdsa-response-valid.xml")

	cert, e := x509.ParseCertificate(fixture.Read(f, fixture.Certificate))
	if e != nil {
		f.Fatal(e)
	}

	keys := []crypto.PublicKey{cert.PublicKey}
	options := protocol.ResponseOptions{Issuer: "https://idp.example/metadata", Audience: "https://sp.example/metadata", Destination: "https://sp.example/acs", ExpectedRequestID: nameRequest, At: fixture.At, ExpectedAuthnContexts: []string{password}}

	d, e := document.Parse(context.Background(), b, document.DefaultLimits())
	if e != nil {
		f.Fatal(e)
	}

	if result, e := protocol.VerifyResponse(context.Background(), d, keys, options); e != nil || result == nil || !result.ResponseAuthenticated() {
		f.Fatalf("invalid positive SAML fixture: %v", e)
	}

	f.Add(b)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<18 {
			t.Skip()
		}

		d, e := document.Parse(t.Context(), raw, document.DefaultLimits())
		if e != nil {
			return
		}

		result, e := protocol.VerifyResponse(context.Background(), d, keys, options)
		if e != nil && result != nil || e == nil && (result == nil || !result.ResponseAuthenticated() || result.InResponseTo() != options.ExpectedRequestID) {
			t.Fatal("inconsistent SAML verification result")
		}
	})
}

func TestAuthnRequestACSSelection(t *testing.T) {
	ctx := context.Background()
	key := testcert.Key(t)

	const (
		first  = "https://sp.example.test/acs-nine"
		second = "https://sp.example.test/acs-one"
	)
	for _, tc := range []struct {
		name       string
		attributes string
		want       string
		first      metadata.Endpoint
		second     metadata.Endpoint
	}{
		{name: "unspecified uses document order", want: first},
		{name: "false is skipped before unspecified", first: metadata.Endpoint{DefaultSet: true}, want: second},
		{name: "all false uses document order", first: metadata.Endpoint{DefaultSet: true}, second: metadata.Endpoint{DefaultSet: true}, want: first},
		{name: "explicit true precedes unspecified", second: metadata.Endpoint{DefaultSet: true, Default: true}, want: second},
		{name: "first explicit true", first: metadata.Endpoint{DefaultSet: true, Default: true}, want: first},
		{name: "explicit index", attributes: ` AssertionConsumerServiceIndex="1"`, want: second},
		{name: "explicit URL", attributes: ` AssertionConsumerServiceURL="` + second + `" ProtocolBinding="` + metadata.HTTPPost + `"`, want: second},
		{name: "unlisted index", attributes: ` AssertionConsumerServiceIndex="2"`},
		{name: "unlisted URL", attributes: ` AssertionConsumerServiceURL="https://evil.test/acs" ProtocolBinding="` + metadata.HTTPPost + `"`},
		{name: "index and URL conflict", attributes: ` AssertionConsumerServiceIndex="1" AssertionConsumerServiceURL="` + second + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.first, tc.second
			a.Binding, a.Location, a.Index = metadata.HTTPPost, first, 9
			b.Binding, b.Location, b.Index = metadata.HTTPPost, second, 1
			options := protocol.RequestOptions{Issuer: sp, Destination: sso, At: testcert.Now(), ACS: []metadata.Endpoint{
				{Binding: metadata.HTTPRedirect, Location: "https://sp.example.test/redirect", Default: true, DefaultSet: true}, a, b,
			}}
			raw := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" ID="_request" Version="2.0" IssueInstant="%s" Destination="%s"%s><saml:Issuer>%s</saml:Issuer></samlp:AuthnRequest>`, protocol.ProtocolNamespace, protocol.AssertionNamespace, testcert.Now().Format(time.RFC3339), sso, tc.attributes, sp)

			d, e := document.Parse(ctx, []byte(raw), document.DefaultLimits())
			if e != nil {
				t.Fatal(e)
			}

			for _, transport := range []string{"POST", "Redirect"} {
				t.Run(transport, func(t *testing.T) {
					checkACSSelection(t, ctx, d, key, options, transport, tc.want)
				})
			}
		})
	}
}

func checkACSSelection(t *testing.T, ctx context.Context, d *document.Document, key crypto.Signer, options protocol.RequestOptions, transport, want string) {
	t.Helper()

	var (
		result *protocol.VerifiedRequest
		err    error
	)

	if transport == "POST" {
		signed, e := xmldsig.SignEnveloped(ctx, d, key, xmldsig.SignOptions{})
		if e != nil {
			t.Fatal(e)
		}

		result, err = protocol.VerifyAuthnRequest(ctx, signed, []crypto.PublicKey{key.Public()}, options)
	} else {
		query, e := binding.SignRedirect(ctx, d, binding.Request, nil, key, binding.Options{SignatureMethod: xmldsig.ECDSASHA256})
		if e != nil {
			t.Fatal(e)
		}

		result, err = protocol.VerifyRedirectRequest(ctx, query, []crypto.PublicKey{key.Public()}, options, binding.Options{})
	}

	if want == "" {
		if err == nil || result != nil {
			t.Fatal("invalid endpoint selection accepted")
		}
	} else if err != nil || result == nil || result.ACS() != want {
		t.Fatalf("want ACS %q, result=%v error=%v", want, result, err)
	}
}

func BenchmarkVerifyResponse(b *testing.B) {
	c := testcert.New(b)

	d, err := protocol.SignResponse(context.Background(), responseSpec(), protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		b.Fatal(err)
	}

	keys := []crypto.PublicKey{c.LeafKey.Public()}
	opt := options()

	b.ReportAllocs()

	for b.Loop() {
		if _, err := protocol.VerifyResponse(context.Background(), d, keys, opt); err != nil {
			b.Fatal(err)
		}
	}
}

func responseSpec() protocol.Response {
	return protocol.Response{ID: "_response", Issuer: idp, Audience: sp, Destination: acs, InResponseTo: nameRequest, IssueInstant: testcert.Now(), Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice", NameIDFormat: protocol.NameIDPersistent, NotBefore: testcert.Now().Add(-time.Minute), NotOnOrAfter: testcert.Now().Add(4 * time.Minute), AuthnInstant: testcert.Now().Add(-time.Minute), AuthnContext: password, SessionIndex: "session-1", Attributes: []protocol.Attribute{{Name: "email", Values: []string{"alice@example.test"}}, {Name: "role", Values: []string{"reader", "editor"}}}}}
}

func options() protocol.ResponseOptions {
	return protocol.ResponseOptions{Issuer: idp, Audience: sp, Destination: acs, ExpectedRequestID: nameRequest, At: testcert.Now(), AllowedNameIDFormats: []string{protocol.NameIDPersistent}, ExpectedAuthnContexts: []string{password}}
}

func removeSignatures(t *testing.T, d *document.Document, all bool) *document.Document {
	t.Helper()

	snapshot, cloneErr := tree.Clone(t.Context(), d)
	if cloneErr != nil {
		t.Fatal(cloneErr)
	}

	var walk func(*tree.Node)

	walk = func(n *tree.Node) {
		out := n.Children[:0]
		for _, c := range n.Children {
			if c.Kind == tree.ElementNode && c.Name == (document.Name{Space: xmldsig.Namespace, Local: "Signature"}) {
				continue
			}

			if all {
				walk(c)
			}

			out = append(out, c)
		}

		n.Children = out
	}
	walk(tree.Root(snapshot))

	b, e := snapshot.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	out, e := document.Parse(t.Context(), b, document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return out
}
