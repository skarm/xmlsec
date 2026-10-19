// Command samlprobe is a private interoperability test adapter.
// Test-only local-file interoperability helper. Not an HTTP endpoint or CLI API.

package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
)

func main() {
	mode := flag.String("mode", "", "mode")
	in := flag.String("in", "", "input")
	out := flag.String("out", "", "output")
	certPath := flag.String("cert", "", "DER cert")
	keyPath := flag.String("key", "", "PKCS8 PEM")
	atString := flag.String("at", "", "explicit UTC instant")

	flag.Parse()
	at, e := time.Parse(time.RFC3339Nano, *atString)
	must(e)
	cert, e := x509.ParseCertificate(read(*certPath))
	must(e)

	method := xmldsig.ECDSASHA256
	if _, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		method = xmldsig.RSASHA256
	}

	var key crypto.Signer

	if *keyPath != "" {
		p, _ := pem.Decode(read(*keyPath))
		if p == nil {
			must(errors.New("key"))
		}

		k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
		must(e)

		var ok bool

		key, ok = k.(crypto.Signer)
		if !ok {
			must(errors.New("private key does not implement crypto.Signer"))
		}
	}

	ctx := context.Background()

	var d *document.Document

	const (
		sp   = "https://sp.example/metadata"
		idp  = "https://idp.example/metadata"
		acs  = "https://sp.example/acs"
		sso  = "https://idp.example/sso"
		auth = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	)

	sk := protocol.SigningKey{Key: key, CertificateDER: cert.Raw, SignatureMethod: method}

	switch *mode {
	case "sign-response":
		d, e = protocol.SignResponse(ctx, protocol.Response{ID: "_response", Issuer: idp, Audience: sp, Destination: acs, InResponseTo: nameRequest, IssueInstant: at, Assertion: protocol.AssertionData{ID: "_assertion", NameID: "alice@example.test", NameIDFormat: protocol.NameIDEmail, NotBefore: at.Add(-time.Minute), NotOnOrAfter: at.Add(5 * time.Minute), AuthnInstant: at.Add(-time.Second), AuthnContext: auth, SessionIndex: "session", Attributes: []protocol.Attribute{{Name: "role", Values: []string{"reader"}}}}}, sk)
	case "verify-response":
		d, e = document.Parse(ctx, read(*in), document.DefaultLimits())
		must(e)
		_, e = protocol.VerifyResponse(ctx, d, []crypto.PublicKey{cert.PublicKey}, protocol.ResponseOptions{Issuer: idp, Audience: sp, Destination: acs, ExpectedRequestID: nameRequest, At: at, ExpectedAuthnContexts: []string{auth}})
	case "sign-request":
		d, e = protocol.SignAuthnRequest(ctx, protocol.AuthnRequest{ID: nameRequest, Issuer: sp, Destination: sso, ACS: acs, IssueInstant: at, NameIDFormat: protocol.NameIDEmail, RequestedContexts: []string{auth}}, sk)
	case "verify-request":
		d, e = document.Parse(ctx, read(*in), document.DefaultLimits())
		must(e)
		_, e = protocol.VerifyAuthnRequest(ctx, d, []crypto.PublicKey{cert.PublicKey}, protocol.RequestOptions{Issuer: sp, Destination: sso, ACS: []metadata.Endpoint{{Binding: metadata.HTTPPost, Location: acs, Index: 0, Indexed: true}}, At: at})
	case "sign-metadata":
		d, e = metadata.Build(ctx, metadata.EntityDescriptor{ID: "_metadata", EntityID: sp, ValidUntil: at.Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: cert.Raw, Use: "signing"}}, AuthnRequestsSigned: true, WantAssertionsSigned: true, Endpoints: map[string][]metadata.Endpoint{"AssertionConsumerService": {{Binding: metadata.HTTPPost, Location: acs, Index: 0, Indexed: true, Default: true}}}}}, at, metadata.Options{})
		must(e)
		d, e = metadata.Sign(ctx, d, key, cert.Raw, method, at, metadata.Options{})
	case "verify-metadata":
		v, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{cert.PublicKey}, Options: metadata.Options{}})
		must(err)

		_, e = v.Verify(ctx, read(*in), at)
	default:
		must(errors.New("mode"))
	}

	must(e)

	if *out != "" {
		b, e := d.XML(ctx)
		must(e)
		must(os.WriteFile(*out, b, 0o600))
	}

	fmt.Println("OK", *mode)
}

func must(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func read(p string) []byte {
	b, e := os.ReadFile(p) // #nosec G304 -- The local interoperability harness supplies fixture paths.
	must(e)

	return b
}
