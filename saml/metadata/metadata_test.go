package metadata_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/xmldsig"
)

const nameSigning = "signing"

type metadataCountingSigner struct {
	crypto.Signer
	calls int
}

func (s *metadataCountingSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(random, digest, options)
}

func TestMetadataSignValidatesOptionsBeforePrivateKeyOperations(t *testing.T) {
	t.Parallel()
	at := testcert.Now()
	d, err := metadata.Build(t.Context(), metadata.EntityDescriptor{
		EntityID: "urn:test:idp", ValidUntil: at.Add(time.Hour),
		IDP: &metadata.RoleDescriptor{Endpoints: map[string][]metadata.Endpoint{
			metadata.SingleSignOnService: {{Binding: metadata.HTTPRedirect, Location: "https://idp.example.test/sso"}},
		}},
	}, at, metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	signer := &metadataCountingSigner{Signer: testcert.Key(t)}
	signed, err := metadata.Sign(t.Context(), d, signer, nil, xmldsig.ECDSASHA256, at, metadata.Options{MaxBytes: -1})
	if signed != nil || !errors.Is(err, metadata.ErrMetadata) || signer.calls != 0 {
		t.Errorf("Sign with invalid options = %p, %v, %d signer calls; want nil, ErrMetadata, 0", signed, err, signer.calls)
	}
	for _, test := range []struct {
		name string
		at   time.Time
		want error
	}{
		{"missing time", time.Time{}, metadata.ErrMetadata},
		{"expired", at.Add(time.Hour), metadata.ErrExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			signer := &metadataCountingSigner{Signer: testcert.Key(t)}
			signed, err := metadata.Sign(t.Context(), d, signer, nil, xmldsig.ECDSASHA256, test.at, metadata.Options{})
			if signed != nil || !errors.Is(err, test.want) || signer.calls != 0 {
				t.Errorf("Sign = %p, %v, %d signer calls; want nil, %v, 0", signed, err, signer.calls, test.want)
			}
		})
	}
	signer.calls = 0
	signed, err = metadata.Sign(t.Context(), d, signer, nil, xmldsig.ECDSASHA256, at, metadata.Options{})
	if signed == nil || err != nil || signer.calls != 1 || len(xmldsig.Signatures(d)) != 0 {
		t.Errorf("Sign with valid options = %p, %v, %d signer calls; want one signature on a new document", signed, err, signer.calls)
	}
}

func TestMetadataSignedAndPinnedTrust(t *testing.T) {
	c := testcert.New(t)
	expired := *c.Leaf
	expired.SerialNumber.SetInt64(13)
	expired.NotBefore = testcert.Now().Add(-48 * time.Hour)
	expired.NotAfter = testcert.Now().Add(-24 * time.Hour)
	old := testcert.Issue(t, &expired, c.Root, &c.LeafKey.PublicKey, c.RootKey)
	spec := metadata.EntityDescriptor{EntityID: "urn:test:idp", ValidUntil: testcert.Now().Add(time.Hour), CacheDuration: 30 * time.Minute, IDP: &metadata.RoleDescriptor{WantAuthnRequestsSigned: true, Keys: []metadata.KeyDescriptor{{Use: nameSigning, CertificateDER: old.Raw}, {Use: nameSigning, CertificateDER: c.TSA.Raw}}, Endpoints: map[string][]metadata.Endpoint{"SingleSignOnService": {{Binding: metadata.HTTPRedirect, Location: "https://idp.example.test/sso"}}}}}

	d, e := metadata.Build(t.Context(), spec, testcert.Now(), metadata.Options{})
	if e != nil {
		t.Fatal(e)
	}

	signed, e := metadata.Sign(t.Context(), d, c.RootKey, c.Root.Raw, xmldsig.ECDSASHA256, testcert.Now(), metadata.Options{})
	if e != nil {
		t.Fatal(e)
	}

	raw, _ := signed.XML(t.Context())

	v, e := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{&c.RootKey.PublicKey}, Options: metadata.Options{}})
	if e != nil {
		t.Fatal(e)
	}

	s, e := v.Verify(t.Context(), raw, testcert.Now())
	if e != nil || !s.AuthenticatedSignature() {
		t.Fatal(e)
	}

	entity, e := s.Find("urn:test:idp", testcert.Now())
	if e != nil {
		t.Fatal(e)
	}

	role, e := entity.Role(metadata.IdentityProvider, testcert.Now())
	if e != nil || len(role.SigningKeys()) != 2 || !role.WantAuthnRequestsSigned() {
		t.Fatal(e)
	}

	keys := role.SigningKeys()
	*keys[0].(*ecdsa.PublicKey) = ecdsa.PublicKey{}

	if !role.SigningKeys()[0].(*ecdsa.PublicKey).Equal(&c.LeafKey.PublicKey) {
		t.Fatal("mutable keys")
	}

	certs := role.Certificates(nameSigning)

	certs[0][0] ^= 1
	if bytes.Equal(certs[0], role.Certificates(nameSigning)[0]) {
		t.Fatal("mutable certs")
	}

	if _, e := s.Find("urn:test:idp", testcert.Now().Add(30*time.Minute)); e == nil {
		t.Fatal("cache expiry")
	}

	wrong, e := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{&c.LeafKey.PublicKey}, Options: metadata.Options{}})
	if e != nil {
		t.Fatal(e)
	}

	if _, e := wrong.Verify(t.Context(), raw, testcert.Now()); e == nil {
		t.Fatal("untrusted signer")
	}

	if _, e := v.Verify(t.Context(), bytes.ReplaceAll(raw, []byte("https://idp.example.test/sso"), []byte("https://attacker.example.test/sso")), testcert.Now()); e == nil {
		t.Fatal("tamper")
	}

	unsigned, _ := d.XML(t.Context())
	if _, e := v.Verify(t.Context(), unsigned, testcert.Now()); e == nil {
		t.Fatal("unsigned")
	}

	if p, e := metadata.ParseTrusted(t.Context(), unsigned, testcert.Now(), metadata.Options{}); e != nil || p.AuthenticatedSignature() {
		t.Fatal(e)
	}
}

func TestAggregateDuplicatesEndpointsAndLimits(t *testing.T) {
	c := testcert.New(t)
	spec := metadata.EntityDescriptor{ID: "_sp", EntityID: "https://sp.example.test/", ValidUntil: testcert.Now().Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{"AssertionConsumerService": {{Index: 1, Default: false, DefaultSet: true, Binding: metadata.HTTPPost, Location: "https://sp.example.test/one"}, {Index: 2, Default: true, Binding: metadata.HTTPPost, Location: "https://sp.example.test/two"}}}}}

	d, e := metadata.Build(t.Context(), spec, testcert.Now(), metadata.Options{})
	if e != nil {
		t.Fatal(e)
	}

	raw, _ := d.XML(t.Context())

	s, e := metadata.ParseTrusted(t.Context(), raw, testcert.Now(), metadata.Options{})
	if e != nil {
		t.Fatal(e)
	}

	entity, _ := s.Find(spec.EntityID, testcert.Now())
	role, _ := entity.Role(metadata.ServiceProvider, testcert.Now())

	ep, e := role.ACS(metadata.HTTPPost, nil)
	if e != nil || ep.Index != 2 {
		t.Fatal(e)
	}

	idx := uint16(1)

	ep, e = role.ACS(metadata.HTTPPost, &idx)
	if e != nil || ep.Index != 1 {
		t.Fatal(e)
	}

	idx = 3
	if _, e = role.ACS(metadata.HTTPPost, &idx); e == nil {
		t.Fatal("arbitrary ACS")
	}

	aggregate := `<md:EntitiesDescriptor xmlns:md="` + metadata.Namespace + `">` + string(raw) + `</md:EntitiesDescriptor>`
	if _, e := metadata.ParseTrusted(t.Context(), []byte(aggregate), testcert.Now(), metadata.Options{}); e != nil {
		t.Fatal(e)
	}

	for _, v := range []string{strings.Replace(aggregate, `</md:EntitiesDescriptor>`, string(raw)+`</md:EntitiesDescriptor>`, 1), strings.ReplaceAll(string(raw), `index="2"`, `index="1"`), strings.ReplaceAll(string(raw), `isDefault="false"`, `isDefault="true"`), strings.ReplaceAll(string(raw), `https://sp.example.test/two`, `http://sp.example.test/two`)} {
		if _, e := metadata.ParseTrusted(t.Context(), []byte(v), testcert.Now(), metadata.Options{}); e == nil {
			t.Fatal("accepted", v)
		}
	}

	if _, e := metadata.ParseTrusted(t.Context(), raw, testcert.Now(), metadata.Options{MaxBytes: 100}); e == nil {
		t.Fatal("size")
	}
}

func TestACSDefaultSelectionUsesDocumentOrder(t *testing.T) {
	c := testcert.New(t)
	for _, tc := range []struct {
		name      string
		endpoints []metadata.Endpoint
		want      uint16
	}{
		{"unspecified prefers first, not smallest index", []metadata.Endpoint{{Index: 9}, {Index: 1}}, 9},
		{"false is skipped for unspecified", []metadata.Endpoint{{Index: 9, DefaultSet: true}, {Index: 5}}, 5},
		{"all false falls back to first", []metadata.Endpoint{{Index: 9, DefaultSet: true}, {Index: 1, DefaultSet: true}}, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoints := append([]metadata.Endpoint(nil), tc.endpoints...)
			for i := range endpoints {
				endpoints[i].Binding = metadata.HTTPPost
				endpoints[i].Location = "https://sp.example.test/acs"
			}

			doc, e := metadata.Build(t.Context(), metadata.EntityDescriptor{EntityID: "urn:test:sp", ValidUntil: testcert.Now().Add(time.Hour), SP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{"AssertionConsumerService": endpoints}}}, testcert.Now(), metadata.Options{})
			if e != nil {
				t.Fatal(e)
			}

			raw, _ := doc.XML(t.Context())

			snapshot, e := metadata.ParseTrusted(t.Context(), raw, testcert.Now(), metadata.Options{})
			if e != nil {
				t.Fatal(e)
			}

			entity, e := snapshot.Find("urn:test:sp", testcert.Now())
			if e != nil {
				t.Fatal(e)
			}

			role, e := entity.Role(metadata.ServiceProvider, testcert.Now())
			if e != nil {
				t.Fatal(e)
			}

			selected, e := role.ACS(metadata.HTTPPost, nil)
			if e != nil || selected.Index != tc.want {
				t.Fatalf("selected=%+v err=%v want %d", selected, e, tc.want)
			}
		})
	}
}

func FuzzMetadata(f *testing.F) {
	f.Add([]byte(`<md:EntitiesDescriptor xmlns:md="` + metadata.Namespace + `"/>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}

		_, _ = metadata.ParseTrusted(t.Context(), b, testcert.Now(), metadata.Options{MaxBytes: 1 << 16})
	})
}

func BenchmarkVerify(b *testing.B) {
	c := testcert.New(b)
	opt := metadata.Options{}
	ctx := b.Context()

	d, err := metadata.Build(ctx, metadata.EntityDescriptor{EntityID: "urn:idp", ValidUntil: testcert.Now().Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: nameSigning, CertificateDER: c.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{"SingleSignOnService": {{Binding: metadata.HTTPRedirect, Location: "https://idp.test/sso"}}}}}, testcert.Now(), opt)
	if err != nil {
		b.Fatal(err)
	}

	d, err = metadata.Sign(ctx, d, c.RootKey, c.Root.Raw, xmldsig.ECDSASHA256, testcert.Now(), opt)
	if err != nil {
		b.Fatal(err)
	}

	raw, err := d.XML(ctx)
	if err != nil {
		b.Fatal(err)
	}

	v, err := metadata.NewVerifier(metadata.Config{TrustedKeys: []crypto.PublicKey{c.RootKey.Public()}, Options: opt})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := v.Verify(ctx, raw, testcert.Now()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCertificateEncodingConsistency(t *testing.T) {
	chain := testcert.New(t)
	base := metadata.EntityDescriptor{EntityID: "urn:test:certificate-encodings", ValidUntil: testcert.Now().Add(time.Hour), IDP: &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{Use: nameSigning, CertificateDER: chain.Leaf.Raw}}, Endpoints: map[string][]metadata.Endpoint{"SingleSignOnService": {{Binding: metadata.HTTPRedirect, Location: "https://idp.example.test/sso"}}}}}
	canonical, err := metadata.Build(t.Context(), base, testcert.Now(), metadata.Options{})
	if err != nil {
		t.Fatal(err)
	}
	canonicalXML, err := canonical.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range testcert.CertificateEncodings(t, chain) {
		t.Run(test.Name, func(t *testing.T) {
			before := bytes.Clone(test.DER)
			spec := base
			role := *base.IDP
			role.Keys = []metadata.KeyDescriptor{{Use: nameSigning, CertificateDER: test.DER}}
			spec.IDP = &role
			built, err := metadata.Build(t.Context(), spec, testcert.Now(), metadata.Options{})
			if test.Valid {
				if err != nil || built == nil {
					t.Fatal(err)
				}
			} else if built != nil || err == nil {
				t.Fatal("builder accepted invalid DER")
			}
			wire := strings.Replace(string(canonicalXML), base64.StdEncoding.EncodeToString(chain.Leaf.Raw), base64.StdEncoding.EncodeToString(test.DER), 1)
			snapshot, err := metadata.ParseTrusted(t.Context(), []byte(wire), testcert.Now(), metadata.Options{})
			if !test.Valid {
				if snapshot != nil || err == nil {
					t.Fatal("metadata parser accepted invalid DER")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			entity, err := snapshot.Find(base.EntityID, testcert.Now())
			if err != nil {
				t.Fatal(err)
			}
			got, err := entity.Role(metadata.IdentityProvider, testcert.Now())
			if err != nil || !bytes.Equal(got.Certificates(nameSigning)[0], test.DER) || !bytes.Equal(before, test.DER) {
				t.Fatal("metadata changed original certificate bytes", err)
			}
		})
	}

	for _, test := range []struct {
		name, start, replacement string
		wantError                bool
	}{
		{"whitespace separating X509Data children", "<ds:X509Data>", "<ds:X509Data> \t\n ", false},
		{"valid mixed KeyInfo type", "<ds:KeyInfo>", "<ds:KeyInfo>certificate for publication", false},
		{"text inside element-only X509Data", "<ds:X509Data>", "<ds:X509Data>certificate for publication", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if bytes.Count(canonicalXML, []byte(test.start)) != 1 {
				t.Fatalf("expected one fixture tag %q", test.start)
			}
			wire := bytes.Replace(canonicalXML, []byte(test.start), []byte(test.replacement), 1)
			snapshot, err := metadata.ParseTrusted(t.Context(), wire, testcert.Now(), metadata.Options{})
			if test.wantError {
				if snapshot != nil || !errors.Is(err, metadata.ErrMetadata) {
					t.Fatalf("ParseTrusted = %v, %v; want no result and ErrMetadata", snapshot, err)
				}
				return
			}
			if err != nil || snapshot == nil {
				t.Fatalf("ParseTrusted = %v, %v; want metadata", snapshot, err)
			}
		})
	}
}

func BenchmarkSelectACS(b *testing.B) {
	for _, size := range []int{1, 128, 1024} {
		endpoints := make([]metadata.Endpoint, size)
		for i := range endpoints {
			endpoints[i] = metadata.Endpoint{Binding: metadata.HTTPPost, Location: fmt.Sprintf("https://sp.test/acs/%d", i), Index: uint16(i), Indexed: true, DefaultSet: true}
		}
		endpoints[size-1].Default = true
		for _, explicit := range []bool{false, true} {
			b.Run(fmt.Sprintf("%d/explicit=%t", size, explicit), func(b *testing.B) {
				var index *uint16
				if explicit {
					value := uint16(size - 1)
					index = &value
				}
				b.ReportAllocs()
				for b.Loop() {
					selected, err := metadata.SelectACS(endpoints, metadata.HTTPPost, index)
					if err != nil || selected.Index != uint16(size-1) {
						b.Fatalf("selection: %+v %v", selected, err)
					}
				}
			})
		}
	}
}

func TestSelectACSPriorityAndBinding(t *testing.T) {
	endpoints := []metadata.Endpoint{
		{Binding: metadata.HTTPRedirect, Location: "redirect", Index: 3, Default: true, DefaultSet: true},
		{Binding: metadata.HTTPPost, Location: "explicit-first", Index: 3, DefaultSet: true},
		{Binding: metadata.HTTPPost, Location: "unspecified", Index: 9},
		{Binding: metadata.HTTPPost, Location: "post-default", Index: 3, Default: true, DefaultSet: true},
	}
	selected, err := metadata.SelectACS(endpoints, metadata.HTTPPost, nil)
	if err != nil || selected.Location != "post-default" {
		t.Fatalf("default priority: %+v %v", selected, err)
	}
	index := uint16(3)
	selected, err = metadata.SelectACS(endpoints, metadata.HTTPPost, &index)
	if err != nil || selected.Location != "explicit-first" {
		t.Fatalf("explicit index priority: %+v %v", selected, err)
	}
	for _, binding := range []string{"missing", ""} {
		if _, err := metadata.SelectACS(endpoints, binding, nil); !errors.Is(err, metadata.ErrMetadata) {
			t.Fatalf("missing binding %q: %v", binding, err)
		}
	}
	index = 65535
	if _, err := metadata.SelectACS(endpoints, metadata.HTTPPost, &index); !errors.Is(err, metadata.ErrMetadata) {
		t.Fatal("missing index accepted", err)
	}
}

func TestMetadataExpiryAttributesRequireValues(t *testing.T) {
	t.Parallel()
	at := testcert.Now()
	for _, level := range []string{"aggregate", "entity", "role"} {
		for _, attribute := range []string{"validUntil", "cacheDuration"} {
			for _, value := range []string{"", " ", "valid", "padded"} {
				t.Run(level+"/"+attribute+"/"+value, func(t *testing.T) {
					t.Parallel()
					padded := value == "padded"
					valid := value == "valid" || padded
					if valid {
						value = "PT60S"
						if attribute == "validUntil" {
							value = at.Add(time.Minute).Format(time.RFC3339Nano)
						}
						if padded {
							value = "&#x9;" + value + " "
						}
					}
					attrs := map[string]string{level: fmt.Sprintf(` %s="%s"`, attribute, value)}
					raw := fmt.Sprintf(`<md:EntitiesDescriptor xmlns:md="%s"%s><md:EntityDescriptor entityID="urn:test:sp"%s><md:SPSSODescriptor protocolSupportEnumeration="%s"%s><md:AssertionConsumerService Binding="%s" Location="https://sp.test/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>`, metadata.Namespace, attrs["aggregate"], attrs["entity"], metadata.Protocol, attrs["role"], metadata.HTTPPost)
					snapshot, err := metadata.ParseTrusted(t.Context(), []byte(raw), at, metadata.Options{})
					if !valid {
						if err == nil || snapshot != nil {
							t.Fatal("empty expiry constraint accepted as absent")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					entity, err := snapshot.Find("urn:test:sp", at)
					if err != nil {
						t.Fatal(err)
					}
					role, err := entity.Role(metadata.ServiceProvider, at)
					if err != nil {
						t.Fatal(err)
					} else if !role.ExpiresAt().Equal(at.Add(time.Minute)) {
						t.Fatalf("effective role expiry = %v, %v; want %v", role.ExpiresAt(), err, at.Add(time.Minute))
					}
					if _, err := entity.Role(metadata.ServiceProvider, at.Add(time.Minute)); err == nil {
						t.Fatal("expiry boundary was inclusive")
					}
				})
			}
		}
	}
}

func TestMetadataProtocolEnumerationUsesXMLWhitespace(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, value string
		accept      bool
	}{
		{"exact", metadata.Protocol, true},
		{"XML space", "urn:unsupported " + metadata.Protocol, true},
		{"XML tab CR LF", "urn:unsupported&#x9;&#xD;&#xA;" + metadata.Protocol, true},
		{"unsupported only", "urn:unsupported", false},
		{"NBSP between", "urn:unsupported&#xA0;" + metadata.Protocol, false},
		{"EMSPACE between", "urn:unsupported&#x2003;" + metadata.Protocol, false},
		{"NBSP prefix", "&#xA0;" + metadata.Protocol, false},
		{"NBSP suffix", metadata.Protocol + "&#xA0;", false},
		{"opaque NBSP item then XML space", "urn:opaque&#xA0;value " + metadata.Protocol, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			raw := fmt.Sprintf(`<md:EntityDescriptor xmlns:md="%s" entityID="urn:test:protocol-list"><md:SPSSODescriptor protocolSupportEnumeration="%s"><md:AssertionConsumerService Binding="%s" Location="https://sp.test/acs" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>`, metadata.Namespace, test.value, metadata.HTTPPost)
			snapshot, err := metadata.ParseTrusted(t.Context(), []byte(raw), at, metadata.Options{})
			if !test.accept {
				if err == nil || snapshot != nil {
					t.Fatal("SAML2 role selected without an exact XML-list item")
				}
				return
			}
			if err != nil || snapshot == nil {
				t.Fatalf("XML-list supported role rejected: %v", err)
			}
			entity, err := snapshot.Find("urn:test:protocol-list", at)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entity.Role(metadata.ServiceProvider, at); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRoleAttributeNamespace(t *testing.T) {
	const assertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	for _, tc := range []struct {
		role                    metadata.RoleType
		endpoint, attrNamespace string
		valid                   bool
	}{
		{metadata.IdentityProvider, metadata.SingleSignOnService, assertion, true},
		{metadata.AttributeAuthority, metadata.AttributeService, assertion, true},
		{metadata.IdentityProvider, metadata.SingleSignOnService, metadata.Namespace, false},
		{metadata.AuthenticationAuthority, metadata.AuthnQueryService, assertion, false},
	} {
		t.Run(string(tc.role)+"/"+tc.attrNamespace, func(t *testing.T) {
			raw := fmt.Sprintf(`<EntityDescriptor xmlns="%s" entityID="urn:test:role"><%s protocolSupportEnumeration="%s"><%s Binding="%s" Location="https://role.test/service"/><a:Attribute xmlns:a="%s" Name="org"/></%s></EntityDescriptor>`, metadata.Namespace, tc.role, metadata.Protocol, tc.endpoint, metadata.SOAP, tc.attrNamespace, tc.role)
			set, err := metadata.ParseTrusted(t.Context(), []byte(raw), testcert.Now(), metadata.Options{})
			if tc.valid {
				if err != nil || set == nil {
					t.Fatalf("ParseTrusted returned %v, want the role with its advertised attribute", err)
				}
			} else if !errors.Is(err, metadata.ErrMetadata) || set != nil {
				t.Fatalf("unexpected attribute accepted: set=%v, err=%v", set != nil, err)
			}
		})
	}
}

func TestMetadataKeyUse(t *testing.T) {
	cert := base64.StdEncoding.EncodeToString(testcert.New(t).Leaf.Raw)
	at := testcert.Now()
	for _, tc := range []struct {
		attribute                  string
		signing, encryption, valid bool
	}{
		{"", true, true, true},
		{` use="signing"`, true, false, true},
		{` use="encryption"`, false, true, true},
		{` use=""`, false, false, false},
		{` use=" signing "`, false, false, false},
	} {
		t.Run("descriptor"+tc.attribute, func(t *testing.T) {
			raw := fmt.Sprintf(`<EntityDescriptor xmlns="%s" entityID="urn:test:key"><IDPSSODescriptor protocolSupportEnumeration="%s"><KeyDescriptor%s><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="%s" Location="https://role.test/service"/></IDPSSODescriptor></EntityDescriptor>`, metadata.Namespace, metadata.Protocol, tc.attribute, cert, metadata.HTTPRedirect)
			set, err := metadata.ParseTrusted(t.Context(), []byte(raw), at, metadata.Options{})
			if !tc.valid {
				if set != nil || !errors.Is(err, metadata.ErrMetadata) {
					t.Fatalf("invalid key use accepted: set=%v, err=%v", set != nil, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			entity, err := set.Find("urn:test:key", at)
			if err != nil {
				t.Fatal(err)
			}
			role, err := entity.Role(metadata.IdentityProvider, at)
			if err != nil || (len(role.SigningKeys()) == 1) != tc.signing || (len(role.EncryptionKeys()) == 1) != tc.encryption {
				t.Fatalf("key use %q: signing=%d, encryption=%d, err=%v", tc.attribute, len(role.SigningKeys()), len(role.EncryptionKeys()), err)
			}
		})
	}
}
