// Copyright 2015 The Go Authors. All rights reserved.
// The upstream license also records Copyright (c) 2015, 2018, 2019 Opsmate, Inc.
// and Copyright (c) 2009 The Go Authors. All rights reserved.
// Adapted from software.sslmate.com/src/go-pkcs12 v0.7.0, pbkdf.go
// (commit 783a42d0116eddc32ca2216d9b4ff4ee6211b736), under BSD-3-Clause.
// Source: https://github.com/SSLMate/go-pkcs12/blob/783a42d0116eddc32ca2216d9b4ff4ee6211b736/pbkdf.go
// The complete source license is in licenses/BSD-3-Clause-PKCS12.txt.

package keys

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/asn1"
	"unicode/utf8"

	"github.com/skarm/xmlsec/internal/der"
)

func oidSHA1() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26} }

func oidSHA256() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} }

func oidSHA384() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2} }

func oidSHA512() asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3} }

func repeatBlock(pattern []byte, size int) []byte {
	if len(pattern) == 0 {
		return nil
	}

	n := size * ((len(pattern) + size - 1) / size)

	return bytes.Repeat(pattern, (n+len(pattern)-1)/len(pattern))[:n]
}

func bmpPassword(password []byte) ([]byte, error) {
	if !utf8.Valid(password) {
		return nil, ErrPolicy
	}

	out := make([]byte, 0, len(password)*2+2)
	for len(password) > 0 {
		r, size := utf8.DecodeRune(password)
		password = password[size:]

		if r > 0xffff {
			clear(out)
			return nil, ErrPolicy
		}

		out = append(out, byte((r>>8)&0xff), byte(r&0xff))
	}

	return append(out, 0, 0), nil
}

// Password bytes are UTF-8 content, not a NUL-terminated API argument. Neither
// an embedded U+0000 nor U+FEFF is discarded or interpreted as framing.
func validPKCS12Password(password []byte) bool { return utf8.Valid(password) }

func classicMACKey(state *passwordState, hash crypto.Hash, salt []byte, iterations int) ([]byte, error) {
	if !state.acceptHash(hash) || len(salt) < 8 || len(salt) > 64 {
		return nil, ErrPolicy
	}

	if err := state.charge(iterations, 1); err != nil {
		return nil, err
	}

	password, err := bmpPassword(state.password)
	if err != nil {
		return nil, err
	}
	defer clear(password)

	h := hash.New()
	d := bytes.Repeat([]byte{3}, h.BlockSize())

	s, p := repeatBlock(salt, h.BlockSize()), repeatBlock(password, h.BlockSize())
	defer clear(p)

	h.Write(d)
	h.Write(s)
	h.Write(p)
	out := h.Sum(nil)

	for i := 1; i < iterations; i++ {
		if i%1024 == 0 {
			if err := state.ctx.Err(); err != nil {
				clear(out)
				return nil, err
			}
		}

		h.Reset()
		h.Write(out)
		out = h.Sum(out[:0])
	}

	if err := state.ctx.Err(); err != nil {
		clear(out)
		return nil, err
	}

	return out, nil
}

func digestHash(v asn1.RawValue) (crypto.Hash, error) {
	oid, param, err := algorithm(v)
	if err != nil {
		return 0, err
	}

	if len(param.FullBytes) > 0 && !der.Is(param, 0, asn1.TagNull, false) {
		return 0, ErrFormat
	}

	switch {
	case oid.Equal(oidSHA1()):
		return crypto.SHA1, nil
	case oid.Equal(oidSHA256()):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384()):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512()):
		return crypto.SHA512, nil
	}

	return 0, ErrPolicy
}

func pkcs12MACKey(state *passwordState, mac asn1.RawValue) (crypto.Hash, []byte, []byte, error) {
	f, err := der.Sequence(mac, 2, 3)
	if err != nil || !der.Is(f[1], 0, asn1.TagOctetString, false) {
		return 0, nil, nil, ErrFormat
	}

	info, err := der.Sequence(f[0], 2, 2)
	if err != nil || !der.Is(info[1], 0, asn1.TagOctetString, false) {
		return 0, nil, nil, ErrFormat
	}

	oid, params, err := algorithm(info[0])
	if err != nil {
		return 0, nil, nil, err
	}

	if oid.Equal(oidPBMAC1()) {
		// RFC 9879: outer macSalt/iterations are syntactic placeholders only.
		if len(f) == 3 {
			if !der.Is(f[2], 0, asn1.TagInteger, false) {
				return 0, nil, nil, ErrFormat
			}
		}

		p, err := der.Sequence(params, 2, 2)
		if err != nil {
			return 0, nil, nil, ErrFormat
		}

		hash, err := hmacHash(p[1])
		if err != nil {
			return 0, nil, nil, err
		}

		if len(info[1].Bytes) != hash.Size() {
			return 0, nil, nil, ErrFormat
		}

		kdf, err := parseKDF(p[0], hash.Size(), true)
		if err == nil && (!sha2(kdf.hash) || kdf.keyBytes != hash.Size() && (!state.allowNonDefaultMACKeyLength || kdf.keyBytes < 16)) {
			err = ErrPolicy
		}

		if err != nil {
			return 0, nil, nil, err
		}

		key, err := state.derive(kdf.hash, kdf.salt, kdf.iterations, kdf.keyBytes)

		return hash, key, info[1].Bytes, err
	}

	hash, err := digestHash(info[0])
	if err != nil {
		return 0, nil, nil, err
	}

	if len(info[1].Bytes) != hash.Size() {
		return 0, nil, nil, ErrFormat
	}

	iterations := 1
	if len(f) == 3 {
		iterations, err = integer(f[2])
		if err != nil {
			return 0, nil, nil, err
		}
	}

	key, err := classicMACKey(state, hash, f[1].Bytes, iterations)

	return hash, key, info[1].Bytes, err
}

func verifyPKCS12MAC(state *passwordState, mac asn1.RawValue, message []byte) error {
	hash, key, expected, err := pkcs12MACKey(state, mac)
	if err != nil {
		return err
	}
	defer clear(key)

	h := hmac.New(hash.New, key)
	if _, err := (derParts{message}).write(state.ctx, h); err != nil {
		return err
	}

	if !hmac.Equal(expected, h.Sum(nil)) {
		return ErrDecrypt
	}

	return state.ctx.Err()
}

func encodePKCS12MAC(state *passwordState, message []byte, options PKCS12Options) ([]byte, error) {
	return encodePKCS12MACParts(state, derParts{message}, options)
}

func encodePKCS12MACParts(state *passwordState, message derParts, options PKCS12Options) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	hash := options.Encryption.Hash

	var (
		key, alg []byte
		err      error
	)
	if options.ClassicMAC {
		key, err = classicMACKey(state, hash, salt, options.Encryption.Iterations)
		oid := oidSHA256()

		switch hash {
		case crypto.SHA384:
			oid = oidSHA384()
		case crypto.SHA512:
			oid = oidSHA512()
		}

		alg = der.Seq(der.OID(oid), []byte{5, 0})
	} else {
		key, err = state.derive(hash, salt, options.Encryption.Iterations, hash.Size())
		params := der.Seq(kdfEncoding(salt, options.Encryption.Iterations, hash.Size(), hash), der.Seq(der.OID(hmacOID(hash)), []byte{5, 0}))
		alg = der.Seq(der.OID(oidPBMAC1()), params)
	}

	if err != nil {
		return nil, err
	}

	defer clear(key)

	h := hmac.New(hash.New, key)
	if _, err := message.write(state.ctx, h); err != nil {
		return nil, err
	}

	return der.Seq(der.Seq(alg, der.Octets(h.Sum(nil))), der.Octets(salt), der.Int(options.Encryption.Iterations)), state.ctx.Err()
}
