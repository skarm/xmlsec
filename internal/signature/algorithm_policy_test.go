package signature_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/skarm/xmlsec/internal/der"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
)

func TestPSSRequiresMatchingHashMGFAndExactSaltProfile(t *testing.T) {
	t.Parallel()

	digest := der.Seq(der.OID(signature.SHA256()), []byte{5, 0})
	otherDigest := der.Seq(der.OID(signature.SHA384()), []byte{5, 0})
	field := func(tag int, content []byte) []byte { return der.Ctx(tag, content) }
	mgf := der.Seq(der.OID(signature.MGF1()), digest)
	validFields := [][]byte{field(0, digest), field(1, mgf), field(2, der.Int(32))}
	for _, test := range []struct {
		name   string
		fields [][]byte
		want   bool
	}{
		{"supported explicit profile", validFields, true},
		{"missing salt", validFields[:2], false},
		{"extra trailer parameter", append(append([][]byte{}, validFields...), field(3, der.Int(1))), false},
		{"wrong hash context tag", [][]byte{field(1, digest), validFields[1], validFields[2]}, false},
		{"malformed hash identifier", [][]byte{field(0, der.Int(1)), validFields[1], validFields[2]}, false},
		{"legacy hash refused", [][]byte{field(0, der.Seq(der.OID(signature.SHA1()))), validFields[1], validFields[2]}, false},
		{"wrong MGF context tag", [][]byte{validFields[0], field(2, mgf), validFields[2]}, false},
		{"wrong MGF algorithm", [][]byte{validFields[0], field(1, der.Seq(der.OID(signature.RSA()), digest)), validFields[2]}, false},
		{"missing MGF hash", [][]byte{validFields[0], field(1, der.Seq(der.OID(signature.MGF1()))), validFields[2]}, false},
		{"different MGF hash", [][]byte{validFields[0], field(1, der.Seq(der.OID(signature.MGF1()), otherDigest)), validFields[2]}, false},
		{"short salt", [][]byte{validFields[0], validFields[1], field(2, der.Int(31))}, false},
		{"long salt", [][]byte{validFields[0], validFields[1], field(2, der.Int(33))}, false},
		{"salt wrong tag", [][]byte{validFields[0], validFields[1], field(2, der.Octets([]byte{32}))}, false},
		{"salt wrong context tag", [][]byte{validFields[0], validFields[1], field(3, der.Int(32))}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			algorithm := pkix.AlgorithmIdentifier{Algorithm: signature.PSS(), Parameters: asn1.RawValue{FullBytes: der.Seq(test.fields...)}}
			hash, mode, err := signature.Details(algorithm)
			if test.want {
				if err != nil || hash != crypto.SHA256 || mode != "pss" {
					t.Fatal("valid PSS profile refused", hash, mode, err)
				}
			} else if !errors.Is(err, signature.Err) || hash != 0 || mode != "" {
				t.Fatal("unsupported PSS profile accepted", hash, mode, err)
			}
		})
	}
	if _, _, err := signature.Details(pkix.AlgorithmIdentifier{Algorithm: signature.PSS(), Parameters: asn1.RawValue{FullBytes: []byte{48, 128}}}); !errors.Is(err, signature.Err) {
		t.Fatal("malformed DER parameters accepted", err)
	}
}

func TestVerifyDigestAgainstStandardCryptoImplementations(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := testcert.Key(t)
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		message := []byte("independently signed digest")
		h := hash.New()
		_, _ = h.Write(message)
		digest := h.Sum(nil)
		for _, mode := range []string{"ecdsa", "rsa", "pss"} {
			t.Run(hash.String()+"/"+mode, func(t *testing.T) {
				t.Parallel()

				public := ecKey.Public()
				var value []byte
				var err error
				if mode == "ecdsa" {
					value, err = ecdsa.SignASN1(rand.Reader, ecKey, digest)
				} else {
					public = rsaKey.Public()
					if mode == "rsa" {
						value, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
					} else {
						value, err = rsa.SignPSS(rand.Reader, rsaKey, hash, digest, &rsa.PSSOptions{Hash: hash, SaltLength: hash.Size()})
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				algorithm, err := signature.Select(public, hash, mode == "pss")
				if err != nil {
					t.Fatal(err)
				}
				if err := signature.VerifyDigest(public, algorithm, digest, value); err != nil {
					t.Fatal("independent valid signature rejected", err)
				}
				changed := bytes.Clone(digest)
				changed[0] ^= 1
				if err := signature.VerifyDigest(public, algorithm, changed, value); err == nil {
					t.Fatal("changed digest accepted")
				}
				if err := signature.VerifyDigest(public, algorithm, digest[:len(digest)-1], value); !errors.Is(err, signature.Err) {
					t.Fatal("short digest accepted", err)
				}
				other := ecKey.Public()
				if mode == "ecdsa" {
					other = rsaKey.Public()
				}
				if err := signature.VerifyDigest(other, algorithm, digest, value); !errors.Is(err, signature.Err) {
					t.Fatal("wrong key family accepted", err)
				}
			})
		}
	}
	algorithm, err := signature.Select(rsaKey.Public(), crypto.SHA256, true)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("fixed-length salt profile"))
	value, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 31})
	if err != nil {
		t.Fatal(err)
	}
	if err := signature.VerifyDigest(rsaKey.Public(), algorithm, digest[:], value); !errors.Is(err, signature.Err) {
		t.Fatal("non-profile PSS salt accepted", err)
	}
}
