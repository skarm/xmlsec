package binding_test

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
)

func TestPOST(t *testing.T) {
	d, e := document.Parse(t.Context(), []byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request"/>`), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	relay := `opaque + & = " ' <> state`

	form, e := binding.EncodePOST(t.Context(), d, binding.Request, &relay, binding.POSTLimits{})
	if e != nil {
		t.Fatal(e)
	}

	m, e := binding.DecodePOST(t.Context(), form, binding.Request, binding.POSTLimits{})
	if e != nil {
		t.Fatal(e)
	}

	r, ok := m.RelayState()
	if !ok || r != relay || m.Parameter() != binding.Request {
		t.Fatal("state")
	}

	a, _ := d.XML(t.Context())

	b, _ := m.UnverifiedDocument().XML(t.Context())
	if !bytes.Equal(a, b) {
		t.Fatal("document")
	}

	html, e := binding.RenderPOSTForm(t.Context(), "https://idp.example.test/sso", d, binding.Request, &relay, binding.POSTLimits{})
	if e != nil || bytes.Contains(html, []byte(`<script>`)) || bytes.Contains(html, []byte(relay)) {
		t.Fatal("HTML escape", e)
	}

	for _, raw := range []string{string(form) + "&SAMLRequest=x", string(form) + "&RelayState=x", string(form) + "&SAMLResponse=x", string(form) + "&Signature=x", string(form) + "&other=x", "SAMLRequest=%", "SAMLRequest=AA==", "SAMLRequest=AB==", url.Values{"SAMLRequest": []string{"AA=="}, "RelayState": []string{strings.Repeat("x", 81)}}.Encode()} {
		if m, e := binding.DecodePOST(t.Context(), []byte(raw), binding.Request, binding.POSTLimits{}); m != nil || e == nil {
			t.Fatal("accepted", raw)
		}
	}

	if m, e := binding.DecodePOST(t.Context(), form, binding.Response, binding.POSTLimits{}); m != nil || e == nil {
		t.Fatal("wrong kind")
	}

	if _, e := binding.RenderPOSTForm(t.Context(), "javascript:alert(1)", d, binding.Request, nil, binding.POSTLimits{}); e == nil {
		t.Fatal("URL")
	}

	if _, e := binding.EncodePOST(t.Context(), d, binding.Request, nil, binding.POSTLimits{MaxFormBytes: 4}); e == nil {
		t.Fatal("limit")
	}
}

func FuzzPOST(f *testing.F) {
	f.Add([]byte("SAMLResponse=AA%3D%3D"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}

		_, _ = binding.DecodePOST(t.Context(), b, binding.Response, binding.POSTLimits{MaxFormBytes: 1 << 16, MaxXMLBytes: 1 << 16})
	})
}
