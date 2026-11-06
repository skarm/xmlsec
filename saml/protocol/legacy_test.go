package protocol_test

import (
	"bytes"
	"crypto"
	"crypto/fips140"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

// The 2005 SAML Conformance section 4 baseline is available only through
// explicit algorithm policy. It does not replace modern default algorithms.
func TestLegacySAMLAlgorithms(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy algorithms are disabled in FIPS mode")
	}
	signer, recipient := encryptionKey(t), encryptionKey(t)
	policy := xmldsig.LegacyVerificationPolicy()
	key := protocol.SigningKey{Key: signer, SignatureMethod: xmldsig.RSASHA1, DigestMethod: xmldsig.SHA1, Policy: policy}
	if _, err := protocol.SignResponse(t.Context(), responseSpec(), key); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatalf("verification permission enabled legacy generation: %v", err)
	}
	key.Policy.AllowLegacySigning = true
	for _, algorithm := range []string{xmlenc.AES128CBC, xmlenc.AES256CBC, xmlenc.TripleDESCBC} {
		for _, transport := range []string{xmlenc.RSA15, xmlenc.RSAOAEP10} {
			spec := responseSpec()
			data := xmlenc.Options{DataAlgorithm: algorithm, AllowLegacy: true}
			if transport == xmlenc.RSA15 {
				data.KeyTransportAlgorithm = transport
			} else {
				data.OAEP = &xmlenc.OAEPParameters{Algorithm: transport, Hash: crypto.SHA1, AllowLegacy: true}
			}
			spec.Encryption = &protocol.EncryptionOptions{Targets: protocol.EncryptAssertion | protocol.EncryptNameID | protocol.EncryptAttributes, Recipient: &recipient.PublicKey, Data: data}
			d, err := protocol.SignResponse(t.Context(), spec, key)
			if err != nil {
				t.Fatal(transport, err)
			}
			opts := options()
			opts.Policy = policy
			opts.Decryption = &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}, Data: data}
			result, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{signer.Public()}, opts)
			if err != nil || result == nil || result.NameID() != "alice" {
				t.Fatalf("legacy SAML exchange %s: %v", transport, err)
			}
			if result, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{signer.Public()}, options()); result != nil || err == nil {
				t.Fatal("default policy accepted a legacy exchange")
			}
		}
	}
}

func TestSAMLSharedSecretAndCanonicalXML(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy HMAC-SHA1 is disabled in FIPS mode")
	}
	provisioned := bytes.Repeat([]byte{0x47}, 32)
	secret, err := protocol.NewSharedSecret(provisioned)
	if err != nil {
		t.Fatal(err)
	}
	clear(provisioned)
	wrong, err := protocol.NewSharedSecret(bytes.Repeat([]byte{0x48}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{xmldsig.HMACSHA1, xmldsig.HMACSHA256} {
		policy := xmldsig.HMACPolicy()
		if method == xmldsig.HMACSHA1 {
			policy = xmldsig.LegacyHMACPolicy()
		}
		key := protocol.SigningKey{Secret: &secret, SignatureMethod: method, Canonicalization: c14n.Canonical10, Policy: policy}
		if method == xmldsig.HMACSHA1 {
			key.DigestMethod = xmldsig.SHA1
		}
		d, err := protocol.SignResponse(t.Context(), responseSpec(), key)
		if err != nil {
			t.Fatal(method, err)
		}
		opts := options()
		opts.Policy = policy
		result, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{wrong, secret}, opts)
		if err != nil || result == nil || result.NameID() != "alice" {
			t.Fatalf("explicit SAML MAC: %v", err)
		}
		for _, keys := range [][]crypto.PublicKey{{wrong}, {bytes.Repeat([]byte{0x47}, 32)}, {testcert.Key(t).Public()}} {
			if result, err := protocol.VerifyResponse(t.Context(), d, keys, opts); result != nil || err == nil {
				t.Fatal("wrong secret, byte-slice or public key became trusted HMAC credential")
			}
		}
		if result, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{secret}, options()); result != nil || err == nil {
			t.Fatal("default policy accepted HMAC")
		}
		key.Key = testcert.Key(t)
		if _, err := protocol.SignResponse(t.Context(), responseSpec(), key); err == nil {
			t.Fatal("ambiguous public-key/MAC credentials accepted")
		}
	}
}
