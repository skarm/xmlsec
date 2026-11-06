package xmlenc_test

import (
	"bytes"
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"github.com/skarm/xmlsec/xmlenc"
)

func TestRSA15ExplicitPolicyAndSessionKey(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy RSA transport is disabled in FIPS mode")
	}
	k := key(t)
	options := xmlenc.Options{KeyTransportAlgorithm: xmlenc.RSA15, AllowLegacy: true}
	d, err := xmlenc.EncryptBytes(t.Context(), []byte("legacy recipient"), &k.PublicKey, options)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := d.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wrappedValue := d.Root().Children()[1].Children()[0].Children()[1].Children()[0].Text()
	wrapped, err := base64.StdEncoding.DecodeString(wrappedValue)
	if err != nil {
		t.Fatal(err)
	}
	// Decode the transport with the standard library, independently of XMLENC.
	secret, err := rsa.DecryptPKCS1v15(rand.Reader, k, wrapped) //nolint:staticcheck // Independent decoding of locally generated known-valid legacy test ciphertext.
	if err != nil || len(secret) != 32 {
		t.Fatalf("PKCS#1 v1.5 session key: %v", err)
	}
	clear(secret)
	provider := &rsa15Provider{PrivateKey: k}
	plain, err := xmlenc.DecryptBytes(t.Context(), d, provider, options)
	if err != nil || string(plain) != "legacy recipient" || provider.sessionBytes != 32 {
		t.Fatalf("session-key provider contract: %q %v (%d)", plain, err, provider.sessionBytes)
	}
	for _, policy := range []xmlenc.Options{{}, {AllowLegacy: true}, {KeyTransportAlgorithm: xmlenc.RSA15}, {KeyTransportAlgorithm: xmlenc.RSA15, AllowLegacy: true, OAEP: &xmlenc.OAEPParameters{}}} {
		if out, err := xmlenc.DecryptBytes(t.Context(), d, provider, policy); out != nil || err == nil {
			t.Fatal("RSA15 accepted without exact explicit policy")
		}
	}
	corrupt := bytes.Replace(raw, []byte(wrappedValue), []byte(base64.StdEncoding.EncodeToString(make([]byte, k.Size()))), 1)
	if out, err := xmlenc.DecryptBytes(t.Context(), parse(t, corrupt), provider, options); out != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatalf("bad padding returned plaintext or a padding oracle: %v", err)
	}
	if _, err := xmlenc.EncryptBytesWithKey(t.Context(), []byte("x"), make([]byte, 32), xmlenc.SymmetricOptions{Data: options}); !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatal("RSA policy silently ignored by direct-key API", err)
	}
}

type rsa15Provider struct {
	*rsa.PrivateKey
	sessionBytes int
}

func (p *rsa15Provider) Decrypt(random io.Reader, ciphertext []byte, options crypto.DecrypterOpts) ([]byte, error) {
	parameters, ok := options.(*rsa.PKCS1v15DecryptOptions) //nolint:staticcheck // Checks the explicit legacy provider's implicit rejection contract.
	if !ok || parameters.SessionKeyLen == 0 {
		return nil, errors.New("implicit session-key rejection required")
	}
	p.sessionBytes = parameters.SessionKeyLen
	return p.PrivateKey.Decrypt(random, ciphertext, options)
}
