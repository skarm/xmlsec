package keyinfo_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
)

const (
	xmlDsKeyNameHintDsKeyName = "<ds:KeyName>hint</ds:KeyName>"
	nameKeyName               = "KeyName"
)

func TestAllowedKeyData(t *testing.T) {
	key := ec(t, elliptic.P256())
	name := document.Name{Space: ns, Local: nameKeyName}

	der := document.Name{Space: ns11, Local: "DEREncodedKeyValue"}
	for _, test := range []struct {
		name    string
		allowed []document.Name
		body    string
		ok      bool
	}{
		{"nil-all-supported", nil, xmlDsKeyNameHintDsKeyName + derXML(t, &key.PublicKey), true},
		{"empty-denies", []document.Name{}, xmlDsKeyNameHintDsKeyName, false},
		{"name-only", []document.Name{name}, xmlDsKeyNameHintDsKeyName, true},
		{"disabled-later-choice", []document.Name{name}, xmlDsKeyNameHintDsKeyName + derXML(t, &key.PublicKey), false},
		{"der-only", []document.Name{der}, derXML(t, &key.PublicKey), true},
		{"bad-qname", []document.Name{{Space: "urn:wrong", Local: nameKeyName}}, xmlDsKeyNameHintDsKeyName, false},
		{"wrapper-not-representation", []document.Name{{Space: ns, Local: "KeyValue"}}, xmlDsKeyNameHintDsKeyName, false},
		{"duplicate", []document.Name{name, name}, xmlDsKeyNameHintDsKeyName, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := parseXML(t, wrap(test.body))

			result, err := keyinfo.Parse(context.Background(), doc, doc.Root(), keyinfo.Options{AllowedKeyData: test.allowed})
			if test.ok {
				if err != nil || result == nil {
					t.Fatal(err)
				}
			} else if result != nil || !errors.Is(err, keyinfo.ErrPolicy) {
				t.Fatal("policy bypass or partial result", err)
			}
		})
	}
	// The KeyValue wrapper does not require permission of its own.
	doc, err := keyinfo.Build(context.Background(), keyinfo.Template{Keys: []keyinfo.PublicKeyValue{{Key: &key.PublicKey}}})
	if err != nil {
		t.Fatal(err)
	}

	if result, err := keyinfo.Parse(context.Background(), doc, doc.Root(), keyinfo.Options{AllowedKeyData: []document.Name{{Space: ns11, Local: "ECKeyValue"}}}); err != nil || len(result.Candidates()) != 1 {
		t.Fatal(err)
	}
}

func TestAllowedKeyDataPreflightBeforeResolver(t *testing.T) {
	retrieval := document.Name{Space: ns, Local: "RetrievalMethod"}
	x509Data := document.Name{Space: ns, Local: "X509Data"}
	calls := 0
	external := &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return io.NopCloser(strings.NewReader(wrap(`<ds:KeyName>remote</ds:KeyName>`))), nil
	})}

	for _, test := range []struct {
		body    string
		allowed []document.Name
	}{
		{`<ds:RetrievalMethod URI="urn:key"/><ds:KeyName>disabled later sibling</ds:KeyName>`, []document.Name{retrieval}},
		{`<ds:RetrievalMethod URI="urn:key"/>`, []document.Name{x509Data}},
		{`<ds:RetrievalMethod URI="urn:key" Type="` + ns + `RSAKeyValue"/>`, []document.Name{retrieval, x509Data}},
		{`<ds:RetrievalMethod URI="urn:key" Type="` + keyinfo.RawX509Certificate + `"/>`, []document.Name{retrieval}},
	} {
		doc := parseXML(t, wrap(test.body))

		result, err := keyinfo.Parse(context.Background(), doc, doc.Root(), keyinfo.Options{AllowedKeyData: test.allowed, External: external})
		if result != nil || !errors.Is(err, keyinfo.ErrPolicy) || calls != 0 {
			t.Fatal("resolver called before local representation preflight", err, calls)
		}
	}
	// Referenced KeyInfo choices remain constrained by the same policy.
	doc := parseXML(t, `<r xmlns:ds="`+ns+`" xmlns:k="`+ns11+`"><ds:KeyInfo><k:KeyInfoReference URI="#target"/></ds:KeyInfo><ds:KeyInfo Id="target"><ds:KeyName>disabled</ds:KeyName></ds:KeyInfo></r>`)
	if result, err := keyinfo.Parse(context.Background(), doc, doc.Root().Children()[0], keyinfo.Options{AllowedKeyData: []document.Name{{Space: ns11, Local: "KeyInfoReference"}}}); result != nil || !errors.Is(err, keyinfo.ErrPolicy) {
		t.Fatal("reference bypassed policy", err)
	}
}

func TestAllowedKeyDataFrozenDuringResolver(t *testing.T) {
	allowed := []document.Name{{Space: ns, Local: "RetrievalMethod"}, {Space: ns11, Local: "DEREncodedKeyValue"}}
	key := ec(t, elliptic.P256())
	remote := `<k:DEREncodedKeyValue xmlns:k="` + ns11 + `">` + enc(mustSPKI(t, &key.PublicKey)) + `</k:DEREncodedKeyValue>`
	options := keyinfo.Options{AllowedKeyData: allowed, External: &keyinfo.ExternalResources{AllowedURIs: []string{uriUrnKey}, Resolver: resolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		allowed[1] = document.Name{Space: ns, Local: nameKeyName}
		return io.NopCloser(strings.NewReader(remote)), nil
	})}}

	doc := parseXML(t, wrap(`<ds:RetrievalMethod URI="urn:key"/>`))
	if result, err := keyinfo.Parse(context.Background(), doc, doc.Root(), options); err != nil || len(result.Candidates()) != 1 {
		t.Fatal("callback changed operation policy", err)
	}
}
