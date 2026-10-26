package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"

	"github.com/skarm/xmlsec/keys"
)

func runKey(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := args[0]
	fs := flag.NewFlagSet("key "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	exec := registerExecutionFlags(fs)
	input := fs.String("in", "", "input key/certificate/CRL file")
	output := fs.String("out", "-", "output path; private material is created with mode 0600")
	algorithm := fs.String("algorithm", "p256", "generate: rsa, p256, p384, p521, ed25519, aes128, aes192, aes256 or hmac256/384/512")
	bits := fs.Int("bits", 3072, "RSA modulus bits (2048..8192)")
	format := fs.String("output-format", namePlain, "private output: plain (PKCS#8), pkcs8 (encrypted) or pkcs12")
	outputPassword := fs.String("output-password-file", "", "password for encrypted output")
	pemOutput := fs.Bool("pem", true, "PEM output; false writes DER (PKCS#12 and symmetric keys always use raw bytes)")
	kind := fs.String(fieldKind, namePublic, "inspect: public, private, certificate, crl or pkcs12")
	certificate := fs.String("certificate", "", "certificate file for PKCS#12 export")

	var extras repeatedFlag
	fs.Var(&extras, "extra-certificate", "extra PKCS#12 certificate; repeatable")
	iterations := fs.Int("iterations", 600000, "PBKDF2 iterations for encrypted export")
	hashName := fs.String("hash", "sha256", "PBKDF2 SHA-2 PRF")
	encryptionBits := fs.Int("encryption-bits", 256, "encrypted key AES bits: 128, 192 or 256")
	classic := fs.Bool("classic-mac", false, "use classic SHA-2 PKCS#12 MAC instead of PBMAC1")
	flags := registerPrivateKeyFlags(fs)

	specific := "in out kind" + privateKeyFlagNames

	switch cmd {
	case "generate":
		specific = "out algorithm bits output-format output-password-file pem certificate extra-certificate iterations hash encryption-bits classic-mac key-max-kdf-work key-min-iterations key-max-iterations"
	case "convert":
		specific = "in out output-format output-password-file pem certificate extra-certificate iterations hash encryption-bits classic-mac" + privateKeyFlagNames
	case namePublic:
		specific += " pem"
	}

	fs = commandFlags(fs, specific, false)

	done, err := parseFlags(fs, args[1:])
	if done || err != nil {
		return err
	}

	ctx, cancel, err := exec.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	options := keyCommand{command: cmd, input: *input, output: *output, algorithm: *algorithm, bits: *bits, format: *format, outputPassword: *outputPassword, pem: *pemOutput, kind: *kind, certificate: *certificate, extra: extras, iterations: *iterations, hash: *hashName, encryptionBits: *encryptionBits, classic: *classic, flags: flags}

	return options.run(ctx, stdout)
}

type keyCommand struct {
	command        string
	input          string
	output         string
	algorithm      string
	format         string
	outputPassword string
	kind           string
	certificate    string
	hash           string
	bits           int
	iterations     int
	encryptionBits int
	pem            bool
	classic        bool
	extra          []string
	flags          *privateKeyFlags
}

func (c keyCommand) run(ctx context.Context, stdout io.Writer) error {
	if c.command == nameInspect {
		return c.inspect(ctx, stdout)
	}

	if c.command == namePublic {
		public, err := c.public(ctx)
		if err != nil {
			return err
		}

		return exportPublic(ctx, c.output, stdout, public, c.pem)
	}

	var (
		signer crypto.Signer
		err    error
	)

	if c.command == "generate" {
		var secret []byte

		signer, secret, err = c.generate()
		if err != nil {
			return err
		}

		if secret != nil {
			defer clear(secret)
			return writeOutputContext(ctx, c.output, stdout, secret)
		}
	} else {
		if err := requiredFlag("in", c.input); err != nil {
			return err
		}

		signer, err = loadPrivateConfigured(ctx, c.input, c.flags)
		if err != nil {
			return err
		}
	}

	raw, err := c.encode(ctx, signer)
	if err != nil {
		return err
	}
	defer clear(raw)

	return writeOutputContext(ctx, c.output, stdout, raw)
}

func (c keyCommand) generate() (crypto.Signer, []byte, error) {
	sizes := map[string]int{"aes128": 16, "aes192": 24, "aes256": 32, "hmac256": 32, "hmac384": 48, "hmac512": 64}
	if size := sizes[c.algorithm]; size != 0 {
		if c.format != namePlain || c.outputPassword != "" {
			return nil, nil, usageError("symmetric keys use raw output without PKCS password options")
		}

		secret := make([]byte, size)
		if _, err := rand.Read(secret); err != nil {
			clear(secret)
			return nil, nil, err
		}

		return nil, secret, nil
	}

	var (
		signer crypto.Signer
		err    error
	)

	switch c.algorithm {
	case nameRSA:
		if c.bits < 2048 || c.bits > 8192 || c.bits%256 != 0 {
			return nil, nil, usageError("RSA -bits must be a multiple of 256 in 2048..8192")
		}

		signer, err = rsa.GenerateKey(rand.Reader, c.bits)
	case "p256", "p384", "p521":
		curve := elliptic.P256()
		if c.algorithm == "p384" {
			curve = elliptic.P384()
		}

		if c.algorithm == "p521" {
			curve = elliptic.P521()
		}

		signer, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, nil, usageError("unsupported key algorithm %q", c.algorithm)
	}

	return signer, nil, err
}

func (c keyCommand) public(ctx context.Context) (crypto.PublicKey, error) {
	if err := requiredFlag("in", c.input); err != nil {
		return nil, err
	}

	if c.kind != "private" && c.flags.format == namePlain {
		public, err := loadPublicContext(ctx, c.input)
		if err == nil {
			return public, nil
		}
	}

	signer, err := loadPrivateConfigured(ctx, c.input, c.flags)
	if err != nil {
		return nil, err
	}

	return signer.Public(), nil
}

func (c keyCommand) inspect(ctx context.Context, stdout io.Writer) error {
	if err := requiredFlag("in", c.input); err != nil {
		return err
	}

	var value any

	switch c.kind {
	case namePublic:
		public, err := loadPublicContext(ctx, c.input)
		if err != nil {
			return err
		}

		value = publicDescription(public)
	case "certificate":
		cert, err := readCertificate(ctx, c.input)
		if err != nil {
			return err
		}

		value = certificateDescription(cert)
	case "crl":
		raw, err := readInputContext(ctx, c.input, nil, keys.DefaultLimits().MaxInputBytes)
		if err != nil {
			return err
		}

		crl, err := keys.ParseCRL(raw, keys.Limits{})
		if err != nil {
			return err
		}

		value = map[string]any{fieldStatus: statusUnverified, fieldIssuer: crl.Issuer.String(), "number": crl.Number, "this_update": crl.ThisUpdate, "next_update": crl.NextUpdate, "revoked_entries": len(crl.RevokedCertificateEntries)}
	case namePKCS12:
		identity, err := c.identity(ctx)
		if err != nil {
			return err
		}

		value = map[string]any{fieldStatus: statusUnverified, "certificate": certificateDescription(identity.Certificate), "extra_certificates": len(identity.ExtraCertificates)}
	case "private":
		signer, err := loadPrivateConfigured(ctx, c.input, c.flags)
		if err != nil {
			return err
		}

		value = publicDescription(signer.Public())
	default:
		return usageError("unsupported inspection -kind")
	}

	return jsonOutput(ctx, c.output, stdout, value)
}

func (c keyCommand) identity(ctx context.Context) (*keys.PKCS12Identity, error) {
	password, err := passwordFromFile(ctx, c.flags.passwordFile)
	if err != nil {
		return nil, err
	}
	defer clear(password)

	raw, err := readInputContext(ctx, c.input, nil, keys.DefaultLimits().MaxInputBytes)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	return keys.ParsePKCS12(ctx, raw, password, c.flags.limits())
}

func (c keyCommand) encode(ctx context.Context, signer crypto.Signer) ([]byte, error) {
	if c.format == namePlain {
		if c.outputPassword != "" {
			return nil, usageError("-output-password-file requires encrypted output")
		}

		raw, err := x509.MarshalPKCS8PrivateKey(signer)
		if err != nil {
			return nil, err
		}

		if c.pem {
			defer clear(raw)
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), nil
		}

		return raw, nil
	}

	password, err := passwordFromFile(ctx, c.outputPassword)
	if err != nil {
		return nil, err
	}
	defer clear(password)

	hash, err := parseHash(c.hash)
	if err != nil {
		return nil, err
	}

	encryption := keys.EncryptionOptions{Iterations: c.iterations, Hash: hash, KeyBits: c.encryptionBits}
	switch c.format {
	case namePkcs8:
		raw, err := keys.MarshalEncryptedPrivate(ctx, signer, password, encryption, c.flags.limits())
		if err != nil {
			return nil, err
		}

		if c.pem {
			defer clear(raw)
			return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: raw}), nil
		}

		return raw, nil
	case namePKCS12:
		identity, err := c.exportIdentity(ctx, signer)
		if err != nil {
			return nil, err
		}

		return keys.MarshalPKCS12(ctx, identity, password, keys.PKCS12Options{Encryption: encryption, ClassicMAC: c.classic}, c.flags.limits())
	default:
		return nil, usageError("-output-format must be plain, pkcs8 or pkcs12")
	}
}

func (c keyCommand) exportIdentity(ctx context.Context, signer crypto.Signer) (keys.PKCS12Identity, error) {
	cert, err := readCertificate(ctx, c.certificate)
	if err != nil {
		return keys.PKCS12Identity{}, err
	}

	identity := keys.PKCS12Identity{PrivateKey: signer, Certificate: cert}
	for _, path := range c.extra {
		cert, err := readCertificate(ctx, path)
		if err != nil {
			return identity, err
		}

		identity.ExtraCertificates = append(identity.ExtraCertificates, cert)
	}

	return identity, nil
}

func exportPublic(ctx context.Context, path string, w io.Writer, public crypto.PublicKey, asPEM bool) error {
	raw, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}

	if asPEM {
		raw = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw})
	}

	return writeOutputContext(ctx, path, w, raw)
}

func publicDescription(public crypto.PublicKey) map[string]any {
	raw, _ := x509.MarshalPKIXPublicKey(public)
	v := map[string]any{fieldStatus: statusUnverified, "spki_sha256": fingerprint(raw)}

	switch k := public.(type) {
	case *rsa.PublicKey:
		v["algorithm"] = nameRSA
		v["bits"] = k.N.BitLen()
	case *ecdsa.PublicKey:
		v["algorithm"] = "ecdsa"
		v["curve"] = k.Curve.Params().Name
	case ed25519.PublicKey:
		v["algorithm"] = "ed25519"
	}

	return v
}

func certificateDescription(c *x509.Certificate) map[string]any {
	return map[string]any{fieldStatus: statusUnverified, "certificate_sha256": fingerprint(c.Raw), "public_key": publicDescription(c.PublicKey), "subject": c.Subject.String(), fieldIssuer: c.Issuer.String(), "serial": c.SerialNumber.String(), "not_before": c.NotBefore, "not_after": c.NotAfter, "is_ca": c.IsCA, "key_usage": c.KeyUsage, "extended_key_usage": c.ExtKeyUsage}
}
