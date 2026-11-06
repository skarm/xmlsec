package metadata_test

import (
	"bytes"
	"crypto"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/xmldsig"
)

func ecpMetadataSpec() metadata.EntityDescriptor {
	return metadata.EntityDescriptor{EntityID: "https://entity.test", ValidUntil: testcert.Now().Add(time.Hour), SP: &metadata.RoleDescriptor{Endpoints: map[string][]metadata.Endpoint{metadata.AssertionConsumerService: {
		{Binding: metadata.HTTPPost, Location: "https://sp.test/post", Indexed: true, Index: 0},
		{Binding: metadata.HoKSSO, ProtocolBinding: metadata.PAOS, Location: "https://sp.test/hok", Indexed: true, Index: 1, SupportedChannelBindings: []string{"tls-server-end-point", "tls-exporter"}},
	}}}, IDP: &metadata.RoleDescriptor{Endpoints: map[string][]metadata.Endpoint{metadata.SingleSignOnService: {{Binding: metadata.HoKSSO, ProtocolBinding: metadata.SOAP, Location: "https://idp.test/ecp", SupportedChannelBindings: []string{"tls-server-end-point"}}}}}}
}

func TestECPMetadataSignedRoundTripAndSelection(t *testing.T) {
	c := testcert.New(t)
	spec := ecpMetadataSpec()
	d, err := metadata.Build(t.Context(), spec, testcert.Now(), metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := metadata.Sign(t.Context(), d, c.LeafKey, c.Leaf.Raw, xmldsig.ECDSASHA256, testcert.Now(), metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := signed.XML(t.Context())
	for _, value := range []string{`hoksso:ProtocolBinding="` + metadata.PAOS + `"`, `Binding="` + metadata.HoKSSO + `"`, `cb:supportsChannelBindings="tls-server-end-point tls-exporter"`} {
		if !bytes.Contains(raw, []byte(value)) {
			t.Fatalf("missing metadata extension %q", value)
		}
	}
	verifier, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{c.LeafKey.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := verifier.Verify(t.Context(), raw, testcert.Now())
	if err != nil {
		t.Fatal(err)
	}
	entity, err := snapshot.Find(spec.EntityID, testcert.Now())
	if err != nil {
		t.Fatal(err)
	}
	role, err := entity.Role(metadata.ServiceProvider, testcert.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := role.ACS(metadata.PAOS, nil); err == nil {
		t.Fatal("HoK-only ACS selected for bearer")
	}
	endpoint, err := role.HoKACS(metadata.PAOS, nil)
	if err != nil || !endpoint.HolderOfKey() || endpoint.Binding != metadata.HoKSSO || endpoint.TransportBinding() != metadata.PAOS || endpoint.Index != 1 || !endpoint.SupportsChannelBinding("tls-exporter") {
		t.Fatalf("HoK selection: %+v %v", endpoint, err)
	}
	endpoint.SupportedChannelBindings[0] = "changed"
	list := role.Endpoints(metadata.AssertionConsumerService)
	list[1].SupportedChannelBindings[0] = "changed"
	again, err := role.HoKACS(metadata.PAOS, nil)
	if err != nil || again.SupportedChannelBindings[0] != "tls-server-end-point" {
		t.Fatal("caller mutated metadata snapshot", err)
	}
	index := uint16(0)
	if _, err := role.HoKACS(metadata.PAOS, &index); err == nil {
		t.Fatal("HoK selection ignored index or selected bearer endpoint")
	}
	tampered := bytes.Replace(raw, []byte("tls-exporter"), []byte("attacker-type"), 1)
	if _, err := verifier.Verify(t.Context(), tampered, testcert.Now()); err == nil {
		t.Fatal("extension metadata was not signed")
	}
}

func TestECPMetadataNamespacesAndListSyntax(t *testing.T) {
	d, err := metadata.Build(t.Context(), ecpMetadataSpec(), testcert.Now(), metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := d.XML(t.Context())
	for _, test := range []struct {
		name   string
		wire   []byte
		want   []string
		accept bool
	}{
		{"arbitrary prefixes", bytes.ReplaceAll(bytes.ReplaceAll(bytes.ReplaceAll(bytes.ReplaceAll(raw, []byte("xmlns:cb="), []byte("xmlns:c=")), []byte("cb:supportsChannelBindings"), []byte("c:supportsChannelBindings")), []byte("xmlns:hoksso="), []byte("xmlns:h=")), []byte("hoksso:ProtocolBinding"), []byte("h:ProtocolBinding")), []string{"tls-server-end-point", "tls-exporter"}, true},
		{"XML whitespace", bytes.Replace(raw, []byte(`tls-server-end-point tls-exporter`), []byte(" tls-server-end-point&#x9;tls-exporter&#xA;"), 1), []string{"tls-server-end-point", "tls-exporter"}, true},
		{"empty present list", bytes.Replace(raw, []byte(`tls-server-end-point tls-exporter`), nil, 1), []string{}, true},
		{"not a boolean", bytes.Replace(raw, []byte(`tls-server-end-point tls-exporter`), []byte("true"), 1), []string{"true"}, true},
		{"non XML whitespace", bytes.Replace(raw, []byte(`tls-server-end-point tls-exporter`), []byte("opaque\u00a0value"), 1), []string{"opaque\u00a0value"}, true},
		{"missing protocol", bytes.Replace(raw, []byte(` hoksso:ProtocolBinding="`+metadata.PAOS+`"`), nil, 1), nil, false},
		{"recursive protocol", bytes.Replace(raw, []byte(`hoksso:ProtocolBinding="`+metadata.PAOS+`"`), []byte(`hoksso:ProtocolBinding="`+metadata.HoKSSO+`"`), 1), nil, false},
		{"wrong namespace", bytes.ReplaceAll(raw, []byte(`xmlns:cb="`+metadata.ChannelBindingNamespace+`"`), []byte(`xmlns:cb="urn:untrusted"`)), nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := metadata.ParseTrusted(t.Context(), test.wire, testcert.Now(), metadata.Options{})
			if (err == nil) != test.accept {
				t.Fatalf("parse: %v", err)
			}
			if !test.accept {
				return
			}
			entity, err := snapshot.Find("https://entity.test", testcert.Now())
			if err != nil {
				t.Fatal(err)
			}
			role, err := entity.Role(metadata.ServiceProvider, testcert.Now())
			if err != nil {
				t.Fatal(err)
			}
			endpoint, err := role.HoKACS(metadata.PAOS, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(endpoint.SupportedChannelBindings, test.want) {
				t.Fatalf("list=%#v, want=%#v", endpoint.SupportedChannelBindings, test.want)
			}
		})
	}
	for _, list := range [][]string{{"tls-server-end-point tls-exporter"}, {""}, {strings.Repeat("x", 257)}} {
		spec := ecpMetadataSpec()
		spec.SP.Endpoints[metadata.AssertionConsumerService][1].SupportedChannelBindings = list
		if _, err := metadata.Build(t.Context(), spec, testcert.Now(), metadata.Options{}); err == nil {
			t.Fatal("invalid source list silently changed during serialization")
		}
	}
}
