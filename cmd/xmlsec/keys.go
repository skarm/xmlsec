package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"os"

	"github.com/skarm/xmlsec/keys"
)

type privateKeyFlags struct {
	format                       string
	passwordFile                 string
	maxKDFWork                   int
	minIterations, maxIterations int
}

func (f *privateKeyFlags) limits() keys.Limits {
	return keys.Limits{MinIterations: f.minIterations, MaxIterations: f.maxIterations, MaxKDFWork: f.maxKDFWork}
}

func registerPrivateKeyFlags(fs *flag.FlagSet) *privateKeyFlags {
	f := &privateKeyFlags{}
	fs.StringVar(&f.format, "key-format", namePlain, "private key format: plain, pkcs8 (encrypted), pkcs12")
	fs.StringVar(&f.passwordFile, "password-file", "", "trusted regular file with one password line; no password in arguments")
	fs.IntVar(&f.maxKDFWork, "key-max-kdf-work", 3000000, "aggregate private key KDF iteration budget")

	fs.IntVar(&f.minIterations, "key-min-iterations", 1000, "minimum permitted import KDF iterations")
	fs.IntVar(&f.maxIterations, "key-max-iterations", 1000000, "maximum permitted iterations per KDF")

	return f
}

func loadPrivateConfigured(ctx context.Context, path string, flags *privateKeyFlags) (crypto.Signer, error) {
	if flags == nil || flags.format == namePlain {
		if flags != nil && flags.passwordFile != "" {
			return nil, errors.New("-password-file requires -key-format pkcs8 or pkcs12")
		}

		return loadPrivateContext(ctx, path)
	}

	if flags.format != namePkcs8 && flags.format != namePKCS12 {
		return nil, errors.New("-key-format must be plain, pkcs8 or pkcs12")
	}

	if flags.passwordFile == "" || flags.passwordFile == "-" {
		return nil, errors.New("encrypted key requires a regular -password-file; stdin is reserved for XML")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	stat, err := os.Stat(flags.passwordFile)
	if err != nil || !stat.Mode().IsRegular() {
		return nil, errors.New("password file must be a trusted regular file")
	}

	password, err := readInputContext(ctx, flags.passwordFile, nil, 1026)
	if err != nil {
		return nil, err
	}
	defer clear(password)

	if bytes.HasSuffix(password, []byte{'\n'}) {
		password = password[:len(password)-1]
		if bytes.HasSuffix(password, []byte{'\r'}) {
			password = password[:len(password)-1]
		}
	}

	if len(password) > 1024 || bytes.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("password file requires one line of at most 1024 bytes")
	}

	raw, err := readInputContext(ctx, path, nil, keys.DefaultLimits().MaxInputBytes)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	limits := flags.limits()
	if flags.format == namePkcs8 {
		return keys.ParseEncryptedPrivate(ctx, raw, password, limits)
	}

	identity, err := keys.ParsePKCS12(ctx, raw, password, limits)
	if err != nil {
		return nil, err
	}

	return identity.PrivateKey, nil
}

func loadPrivateContext(ctx context.Context, path string) (crypto.Signer, error) {
	if path == "-" {
		return nil, errors.New("key must be a file; stdin is reserved for input")
	}

	raw, err := readInputContext(ctx, path, nil, keys.DefaultLimits().MaxInputBytes)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	return keys.ParsePrivate(raw, keys.Limits{})
}

func loadPublicContext(ctx context.Context, path string) (crypto.PublicKey, error) {
	if path == "-" {
		return nil, errors.New("key must be a file; stdin is reserved for input")
	}

	raw, err := readInputContext(ctx, path, nil, keys.DefaultLimits().MaxInputBytes)
	if err != nil {
		return nil, err
	}

	return keys.ParsePublic(raw, keys.Limits{})
}

func readCertificate(ctx context.Context, path string) (*x509.Certificate, error) {
	raw, err := readInputContext(ctx, path, nil, keys.DefaultLimits().MaxInputBytes)
	if err != nil {
		return nil, err
	}

	return keys.ParseCertificate(raw, keys.Limits{})
}

func readCertificates(ctx context.Context, base string, paths []string) ([][]byte, error) {
	if len(paths) > 128 {
		return nil, errors.New("too many certificate files")
	}

	out := make([][]byte, 0, len(paths))
	for _, path := range paths {
		cert, err := readCertificate(ctx, localPath(base, path))
		if err != nil {
			return nil, err
		}

		out = append(out, cert.Raw)
	}

	return out, nil
}

func passwordFromFile(ctx context.Context, path string) ([]byte, error) {
	if path == "" || path == "-" {
		return nil, usageError("password requires a trusted regular file")
	}

	password, err := readInputContext(ctx, path, nil, 1026)
	if err != nil {
		return nil, err
	}

	if bytes.HasSuffix(password, []byte{'\n'}) {
		password = password[:len(password)-1]
		if bytes.HasSuffix(password, []byte{'\r'}) {
			password = password[:len(password)-1]
		}
	}

	if len(password) > 1024 || bytes.ContainsAny(password, "\r\n\x00") {
		clear(password)
		return nil, usageError("password file requires one line of at most 1024 bytes")
	}

	return password, nil
}
