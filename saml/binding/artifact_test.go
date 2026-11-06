package binding_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/saml/binding"
)

// Bindings 3.6.4.1: 2-octet type, 2-octet network-order endpoint index,
// 20-octet SourceID and 20-octet MessageHandle. This vector is assembled directly.
func TestArtifactWireAndHTTP(t *testing.T) {
	wire := append([]byte{0, 4, 1, 2}, bytes.Repeat([]byte{0x31}, 20)...)
	wire = append(wire, bytes.Repeat([]byte{0x42}, 20)...)
	encoded := base64.StdEncoding.EncodeToString(wire)
	a, err := binding.ParseArtifact(encoded)
	if err != nil || a.EndpointIndex != 258 || a.SourceID[0] != 0x31 || a.MessageHandle[19] != 0x42 || a.String() != encoded {
		t.Fatalf("artifact vector: %v", err)
	}
	relay := "opaque +/&"
	form, err := binding.EncodeArtifact(a, &relay)
	if err != nil {
		t.Fatal(err)
	}
	decoded, state, err := binding.DecodeArtifact(form)
	if err != nil || decoded != a || state == nil || *state != relay {
		t.Fatal("form/query round trip")
	}
	for _, bad := range []string{form + "&SAMLart=" + url.QueryEscape(encoded), form + "&RelayState=other", form + "&SAMLResponse=bad", form + "&SigAlg=bad", "SAMLart=%invalid"} {
		if _, _, err := binding.DecodeArtifact(bad); err == nil {
			t.Fatalf("accepted ambiguous/bad artifact %q", bad)
		}
	}
	for _, bad := range []string{"", encoded + "=", base64.StdEncoding.EncodeToString(append([]byte{0, 3}, wire[2:]...)), strings.Repeat("A", 60)} {
		if _, err := binding.ParseArtifact(bad); err == nil {
			t.Fatal("invalid artifact")
		}
	}
	if _, err := binding.ArtifactURL("https://sp.test/acs?SAMLart=existing", a, nil); err == nil {
		t.Fatal("parameter collision")
	}
	long := strings.Repeat("x", 81)
	if _, err := binding.EncodeArtifact(a, &long); err == nil {
		t.Fatal("RelayState length")
	}
	x, err := binding.NewArtifact("https://idp.test/entity", 0)
	if err != nil {
		t.Fatal(err)
	}
	y, err := binding.NewArtifact("https://idp.test/entity", 0)
	if err != nil || x.SourceID != y.SourceID || x.MessageHandle == y.MessageHandle {
		t.Fatal("source/handle generation")
	}
}

func FuzzArtifact(f *testing.F) {
	f.Add("AAQAADE x")
	f.Add(base64.StdEncoding.EncodeToString(make([]byte, 44)))
	f.Fuzz(func(t *testing.T, input string) {
		a, err := binding.ParseArtifact(input)
		if err == nil && a.String() != input {
			t.Fatal("accepted noncanonical artifact")
		}
	})
}

func TestArtifactFormRejectsUnstableRelayState(t *testing.T) {
	t.Parallel()
	a := binding.Artifact{MessageHandle: [20]byte{1}}
	for _, value := range []string{"state\x00suffix", "state\rsuffix", "state\nsuffix"} {
		form, err := binding.ArtifactForm("https://sp.test/acs", a, &value)
		if form != nil || !errors.Is(err, binding.ErrBinding) {
			t.Fatalf("HTML form accepted RelayState %q whose value changes in a browser: %v", value, err)
		}
		// The URL-encoded carrier preserves these opaque bytes and remains valid.
		encoded, err := binding.EncodeArtifact(a, &value)
		if err != nil {
			t.Fatal(err)
		}
		_, relay, err := binding.DecodeArtifact(encoded)
		if err != nil || relay == nil || *relay != value {
			t.Fatal("raw artifact carrier changed opaque RelayState", relay, err)
		}
	}
	for _, value := range []string{strings.Repeat("x", 81), "\xff"} {
		if form, err := binding.ArtifactForm("https://sp.test/acs", a, &value); form != nil || !errors.Is(err, binding.ErrBinding) {
			t.Fatalf("invalid HTML RelayState %q accepted: %v", value, err)
		}
	}
	for _, value := range []string{`opaque +/&"' <é>`, strings.Repeat("x", 80)} {
		if _, err := binding.ArtifactForm("https://sp.test/acs", a, &value); err != nil {
			t.Fatal("printable RelayState rejected", err)
		}
	}
}
