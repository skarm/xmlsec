package ecp_test

import (
	"bytes"
	"net/http"
	"slices"
	"testing"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/ecp"
	"github.com/skarm/xmlsec/saml/proof"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestHoKNegotiationAndAlternatives(t *testing.T) {
	h := http.Header{}
	ecp.AdvertiseHoK(h)
	if !ecp.HoKNegotiated(h) || !ecp.NegotiatedChannelBindings(h) {
		t.Fatal("missing HoK/channel negotiation")
	}
	ecp.Advertise(h)
	if ecp.HoKNegotiated(h) {
		t.Fatal("legacy client negotiated HoK")
	}
	c := testcert.New(t)
	d, err := ecp.HoKChallenge(t.Context(), protocol.AuthnRequest{ID: "_choices", Issuer: "https://sp.test/entity", Destination: "https://idp.test/sso", ACS: "https://sp.test/acs", IssueInstant: testcert.Now()}, protocol.SigningKey{Key: c.LeafKey}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ecp.ParseChallenge(t.Context(), raw, "https://sp.test/resource", binding.SOAPOptions{}); err == nil {
		t.Fatal("HoK-only challenge accepted as bearer")
	}
	const bearer = `<ecp:SubjectConfirmation xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" env:actor="http://schemas.xmlsoap.org/soap/actor/next" env:mustUnderstand="1" Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>`
	mixed := bytes.Replace(raw, []byte(`</env:Header>`), []byte(bearer+`</env:Header>`), 1)
	if _, err := ecp.ParseChallenge(t.Context(), mixed, "https://sp.test/resource", binding.SOAPOptions{}); err != nil {
		t.Fatalf("explicit bearer alternative: %v", err)
	}
	if _, err := ecp.ParseHoKChallenge(t.Context(), mixed, "https://sp.test/resource", c.Leaf.Raw, nil, binding.SOAPOptions{}); err != nil {
		t.Fatalf("HoK alternative: %v", err)
	}
	duplicate := bytes.Replace(mixed, []byte(`</env:Header>`), []byte(bearer+`</env:Header>`), 1)
	if _, err := ecp.ParseHoKChallenge(t.Context(), duplicate, "https://sp.test/resource", c.Leaf.Raw, nil, binding.SOAPOptions{}); err == nil {
		t.Fatal("duplicate method accepted")
	}
	const ownChannel = `<cb:ChannelBindings xmlns:cb="urn:oasis:names:tc:SAML:protocol:ext:channel-binding" env:mustUnderstand="1" Type="tls-server-end-point">AQID</cb:ChannelBindings>`
	misplaced := bytes.Replace(raw, []byte(`</env:Header>`), []byte(ownChannel+`</env:Header>`), 1)
	if _, err := ecp.ParseHoKChallenge(t.Context(), misplaced, "https://sp.test/resource", c.Leaf.Raw, nil, binding.SOAPOptions{}); err == nil {
		t.Fatal("client/IdP channel accepted in SP challenge")
	}
}

func TestHoKChallengeRequiresValidLocalChannelBindings(t *testing.T) {
	t.Parallel()
	c := testcert.New(t)
	channel := protocol.ChannelBinding{Type: ecp.TLSServerEndPoint, Data: []byte{1, 2, 3}}
	challenge, err := ecp.HoKChallenge(t.Context(), protocol.AuthnRequest{
		ID: "_channel", Issuer: "https://sp.test/entity", Destination: "https://idp.test/sso",
		ACS: "https://sp.test/acs", IssueInstant: testcert.Now(), ChannelBindings: []protocol.ChannelBinding{channel},
	}, protocol.SigningKey{Key: c.LeafKey}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := challenge.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, channels := range [][]protocol.ChannelBinding{{channel}, {channel, channel}, {{Type: channel.Type}}} {
		x, err := ecp.ParseHoKChallenge(t.Context(), raw, "https://sp.test/resource", c.Leaf.Raw, channels, binding.SOAPOptions{})
		want := len(channels) == 1 && len(channels[0].Data) != 0
		if (x != nil) != want || (err == nil) != want {
			t.Errorf("ParseHoKChallenge(%v) = %p, %v; want success=%t", channels, x, err, want)
		}
	}
}

func TestHoKChallengePreservesCertificateWithRelativeDistributionPoint(t *testing.T) {
	t.Parallel()
	c := testcert.New(t)
	encodings := testcert.CertificateEncodings(t, c)
	i := slices.IndexFunc(encodings, func(encoding testcert.CertificateEncoding) bool {
		return encoding.Valid && encoding.Name == "relative distribution point"
	})
	if i < 0 {
		t.Fatal("missing relative CRL distribution-point certificate")
	}
	certificate := encodings[i].DER
	challenge, err := ecp.HoKChallenge(t.Context(), protocol.AuthnRequest{
		ID: "_relative", Issuer: "https://sp.test/entity", Destination: "https://idp.test/sso",
		ACS: "https://sp.test/acs", IssueInstant: testcert.Now(),
	}, protocol.SigningKey{Key: c.LeafKey}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := challenge.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := ecp.ParseHoKChallenge(t.Context(), raw, "https://sp.test/resource", certificate, nil, binding.SOAPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	forward, err := exchange.ToIDPEnvelopedXML(t.Context(), proof.Signing{Key: c.LeafKey, Certificate: certificate}, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = forward.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := ecp.VerifyEnvelopedXML(t.Context(), raw, proof.Options{Certificate: certificate})
	if err != nil || verified == nil || !bytes.Equal(verified.Certificate(), certificate) {
		t.Fatalf("verified certificate snapshot: %v", err)
	}
}
