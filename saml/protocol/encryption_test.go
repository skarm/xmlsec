package protocol_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/saml/protocol"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

func encryptionKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// SAML Core 2.0 sections 2.2.4 and 6.2 (Errata E93): encrypt inner
// identifiers/attributes before signing, and entire assertions after signing.
func TestEncryptedResponseTargets(t *testing.T) {
	c, recipient := testcert.New(t), encryptionKey(t)
	for targets := protocol.EncryptionTargets(1); targets < 8; targets++ {
		t.Run(fmt.Sprint(targets), func(t *testing.T) {
			spec := responseSpec()
			spec.Encryption = &protocol.EncryptionOptions{Targets: targets, Recipient: &recipient.PublicKey}
			d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := d.XML(t.Context())
			if err != nil || targets&(protocol.EncryptAssertion|protocol.EncryptNameID) != 0 && bytes.Contains(raw, []byte(">alice<")) || targets&(protocol.EncryptAssertion|protocol.EncryptAttributes) != 0 && bytes.Contains(raw, []byte("alice@example.test")) {
				t.Fatalf("identity disclosed or serialization failed: %v", err)
			}
			opts := options()
			opts.Decryption = &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}
			opts.RequireEncryption = targets
			result, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, opts)
			if err != nil || result == nil {
				t.Fatalf("decrypt/verify: %v", err)
			}
			if result.NameID() != "alice" || result.Encryption() != targets || len(result.Attributes()) != 2 || result.Attributes()[1].Values[1] != "editor" || !result.ResponseAuthenticated() {
				t.Fatal("claims or authenticated encryption targets lost")
			}
			after, _ := d.XML(t.Context())
			if !bytes.Equal(raw, after) {
				t.Fatal("verification mutated the ciphertext snapshot")
			}
			second, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
			if err != nil {
				t.Fatal(err)
			}
			other, _ := second.XML(t.Context())
			if bytes.Equal(raw, other) {
				t.Fatal("encryption reused ciphertext")
			}
			firstNonces, nextNonces := samlGCMNonces(t, d.Root()), samlGCMNonces(t, second.Root())
			if len(firstNonces) == 0 || len(firstNonces) != len(nextNonces) {
				t.Fatal("encrypted data is missing")
			}
			for i, nonce := range firstNonces {
				if bytes.Equal(nonce, nextNonces[i]) {
					t.Fatal("GCM nonce was reused across encryptions")
				}
			}
		})
	}
}

func samlGCMNonces(t *testing.T, element document.Element) [][]byte {
	t.Helper()
	if element.Name() == (document.Name{Space: xmlenc.Namespace, Local: "EncryptedData"}) {
		for _, child := range element.Children() {
			if child.Name() == (document.Name{Space: xmlenc.Namespace, Local: "CipherData"}) {
				raw, err := base64.StdEncoding.DecodeString(child.Children()[0].Text())
				if err != nil || len(raw) < 28 {
					t.Fatalf("XMLENC 1.1 GCM IV/tag: %v", err)
				}
				return [][]byte{raw[:12]}
			}
		}
	}
	var nonces [][]byte
	for _, child := range element.Children() {
		nonces = append(nonces, samlGCMNonces(t, child)...)
	}
	return nonces
}

func TestEncryptedResponsePoliciesAndFailureOrder(t *testing.T) {
	c, recipient, wrong := testcert.New(t), encryptionKey(t), encryptionKey(t)
	spec := responseSpec()
	spec.Encryption = &protocol.EncryptionOptions{Targets: protocol.EncryptAssertion, Recipient: &recipient.PublicKey}
	d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		policy *protocol.DecryptionOptions
		ok     bool
	}{
		{"missing key", nil, false},
		{"wrong key", &protocol.DecryptionOptions{Keys: []crypto.Decrypter{wrong}}, false},
		{"rollover", &protocol.DecryptionOptions{Keys: []crypto.Decrypter{wrong, recipient}}, true},
		{"attempt budget", &protocol.DecryptionOptions{Keys: []crypto.Decrypter{wrong, recipient}, MaxDecryptions: 1}, false},
		{"algorithm mismatch", &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}, Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128GCM}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := options()
			opts.Decryption = tc.policy
			result, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, opts)
			if tc.ok && (err != nil || result == nil) || !tc.ok && (err == nil || result != nil) {
				t.Fatalf("result=%v err=%v", result, err)
			}
		})
	}
	provider := &decryptCounter{PrivateKey: recipient}
	opts := options()
	opts.Decryption = &protocol.DecryptionOptions{Keys: []crypto.Decrypter{provider}}
	// Authentication failure must not reach any private-key operation.
	if result, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{c.TSAKey.Public()}, opts); result != nil || err == nil || provider.calls != 0 {
		t.Fatalf("invalid outer signature reached decryptor: %v, calls %d", err, provider.calls)
	}
	// Ciphertext integrity is still checked when an authenticated sender signs
	// a corrupted tag; no decrypted assertion may be returned.
	corrupt := encryptedEnvelope(t, d, c, func(root *tree.Node) {
		value := find(root, "CipherValue")
		value.Children[0].Data = "AAAA" + value.Children[0].Data[4:]
	})
	if result, err := protocol.VerifyResponse(t.Context(), corrupt, []crypto.PublicKey{c.LeafKey.Public()}, opts); result != nil || !errors.Is(err, protocol.ErrEncryption) {
		t.Fatalf("corrupted ciphertext accepted: %v", err)
	}
	spec.Encryption = nil
	plain, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []protocol.EncryptionTargets{protocol.EncryptAssertion, protocol.EncryptNameID, protocol.EncryptAttributes} {
		opts.RequireEncryption = target
		if result, err := protocol.VerifyResponse(t.Context(), plain, []crypto.PublicKey{c.LeafKey.Public()}, opts); result != nil || !errors.Is(err, protocol.ErrEncryption) {
			t.Fatalf("plaintext downgrade accepted for %d: %v", target, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := protocol.VerifyResponse(ctx, d, []crypto.PublicKey{c.LeafKey.Public()}, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestEncryptedNameIDIsAPolicyValue(t *testing.T) {
	c, recipient := testcert.New(t), encryptionKey(t)
	spec := responseSpec()
	spec.Assertion.NameIDFormat = protocol.NameIDEncrypted
	spec.Encryption = &protocol.EncryptionOptions{Targets: protocol.EncryptNameID, Recipient: &recipient.PublicKey}
	if result, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey}); result != nil || err == nil {
		t.Fatal("NameIDPolicy's encrypted marker was emitted as an inner NameID format")
	}
}

func TestEncryptedResponseAlternativeEncodings(t *testing.T) {
	c, recipient := testcert.New(t), encryptionKey(t)
	spec := responseSpec()
	spec.Encryption = &protocol.EncryptionOptions{Targets: protocol.EncryptAssertion, Recipient: &recipient.PublicKey}
	d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*tree.Node)
		ok     bool
	}{
		{"optional Type absent", func(root *tree.Node) {
			n := find(root, "EncryptedData")
			for i, attr := range n.Attrs {
				if attr.Name.Local == "Type" {
					n.Attrs = append(n.Attrs[:i], n.Attrs[i+1:]...)
					break
				}
			}
		}, true},
		{"Type must be Element", func(root *tree.Node) { set(find(root, "EncryptedData"), "Type", xmlenc.ContentType) }, false},
		{"addressed encrypted key", func(root *tree.Node) {
			set(find(root, "EncryptedData"), "Id", "_data")
			list := xmlutil.Node("xenc", xmlenc.Namespace, "ReferenceList")
			ref := xmlutil.Node("xenc", xmlenc.Namespace, "DataReference")
			xmlutil.Set(ref, "URI", "#_data")
			xmlutil.Add(list, ref)
			xmlutil.Add(find(root, "EncryptedKey"), list)
		}, true},
		{"wrong data reference", func(root *tree.Node) {
			set(find(root, "EncryptedData"), "Id", "_data")
			list := xmlutil.Node("xenc", xmlenc.Namespace, "ReferenceList")
			ref := xmlutil.Node("xenc", xmlenc.Namespace, "DataReference")
			xmlutil.Set(ref, "URI", "#_other")
			xmlutil.Add(list, ref)
			xmlutil.Add(find(root, "EncryptedKey"), list)
		}, false},
		{"multiple recipient keys", func(root *tree.Node) {
			key := find(root, "EncryptedKey")
			snapshot, err := tree.Clone(t.Context(), tree.FromNodes([]*tree.Node{tree.ExtractSubtree(key)}, document.DefaultLimits()))
			if err != nil {
				t.Fatal(err)
			}
			other := tree.Root(snapshot)
			value := find(other, "CipherValue").Children[0]
			value.Data = "AAAA" + value.Data[4:]
			info := key.Parent
			other.Parent = info
			info.Children = append([]*tree.Node{other}, info.Children...)
		}, true},
		{"sibling key", func(root *tree.Node) {
			data := find(root, "EncryptedData")
			for i, child := range data.Children {
				if child.Name.Local == "KeyInfo" {
					key := tree.ImportSubtree(child.Children[0])
					data.Children = append(data.Children[:i], data.Children[i+1:]...)
					xmlutil.Add(find(root, "EncryptedAssertion"), key)
					break
				}
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := encryptedEnvelope(t, d, c, tc.change)
			opts := options()
			opts.Decryption = &protocol.DecryptionOptions{Keys: []crypto.Decrypter{recipient}}
			result, err := protocol.VerifyResponse(t.Context(), changed, []crypto.PublicKey{c.LeafKey.Public()}, opts)
			if tc.ok && (err != nil || result == nil) || !tc.ok && (err == nil || result != nil) {
				t.Fatalf("result=%v err=%v", result, err)
			}
		})
	}
}

func TestEncryptedCBCAndUnsignedAssertion(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy CBC is disabled in FIPS mode")
	}
	c, recipient := testcert.New(t), encryptionKey(t)
	spec := responseSpec()
	spec.Encryption = &protocol.EncryptionOptions{Targets: protocol.EncryptAssertion, Recipient: &recipient.PublicKey, Data: xmlenc.Options{DataAlgorithm: xmlenc.AES128CBC, AllowLegacy: true}}
	d, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	opts := options()
	provider := &decryptCounter{PrivateKey: recipient}
	opts.Decryption = &protocol.DecryptionOptions{Keys: []crypto.Decrypter{provider}, Data: spec.Encryption.Data}
	if _, err := protocol.VerifyResponse(t.Context(), d, []crypto.PublicKey{c.LeafKey.Public()}, opts); err != nil {
		t.Fatal(err)
	}
	provider.calls = 0
	opts.AllowUnsignedResponse = true
	if result, err := protocol.VerifyResponse(t.Context(), removeSignatures(t, d, false), []crypto.PublicKey{c.LeafKey.Public()}, opts); result != nil || !errors.Is(err, protocol.ErrEncryption) || provider.calls != 0 {
		t.Fatalf("unauthenticated CBC reached private provider: %v", err)
	}
	spec.Encryption = nil
	plain, err := protocol.SignResponse(t.Context(), spec, protocol.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	outerOnly := encryptedEnvelope(t, removeSignatures(t, plain, true), c, func(*tree.Node) {})
	opts = options()
	if result, err := protocol.VerifyResponse(t.Context(), outerOnly, []crypto.PublicKey{c.LeafKey.Public()}, opts); result != nil || !errors.Is(err, protocol.ErrSignature) {
		t.Fatal("unsigned assertion accepted without policy")
	}
	opts.AllowUnsignedAssertion = true
	if result, err := protocol.VerifyResponse(t.Context(), outerOnly, []crypto.PublicKey{c.LeafKey.Public()}, opts); err != nil || result == nil || !result.ResponseAuthenticated() {
		t.Fatalf("authenticated envelope-only POST rejected: %v", err)
	}
	opts.AllowUnsignedResponse = true
	if result, err := protocol.VerifyResponse(t.Context(), removeSignatures(t, outerOnly, true), []crypto.PublicKey{c.LeafKey.Public()}, opts); result != nil || !errors.Is(err, protocol.ErrSignature) {
		t.Fatal("both signatures absent accepted")
	}
}

func encryptedEnvelope(t *testing.T, d *document.Document, c testcert.Chain, change func(*tree.Node)) *document.Document {
	t.Helper()
	d = removeSignatures(t, d, false)
	snapshot, err := tree.Clone(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	change(tree.Root(snapshot))
	snapshot, err = tree.Reparse(t.Context(), snapshot, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = xmlsig.Sign(t.Context(), snapshot, snapshot.Root(), xmlsig.SigningKey{Key: c.LeafKey, CertificateDER: c.Leaf.Raw, Method: xmldsig.ECDSASHA256}, true)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

type decryptCounter struct {
	*rsa.PrivateKey
	calls int
}

func (p *decryptCounter) Decrypt(random io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	p.calls++
	return p.PrivateKey.Decrypt(random, ciphertext, opts)
}
