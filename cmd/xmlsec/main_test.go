package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	flagKey            = "-key"
	flagResources      = "-resources"
	flagSignatureIndex = "-signature-index"
	privateKeyPEMType  = "PRIVATE KEY"
	publicKeyPEMType   = "PUBLIC KEY"
	nameExtra          = "extra"
	nameBogus          = "bogus"
	nameCMS            = "cms"
	nameUnknown        = "unknown"
)

func TestCLI(t *testing.T) {
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	private := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	der, err = x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	public := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(public, pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	source := `<r ID="root"><v>value</v></r>`

	var signed, stderr bytes.Buffer
	if err := run(context.Background(), []string{nameSign, flagKey, private}, strings.NewReader(source), &signed, &stderr); err != nil {
		t.Fatal(err)
	}

	var verified bytes.Buffer
	if err := run(context.Background(), []string{nameVerify, flagKey, public, "-root-local", "r"}, bytes.NewReader(signed.Bytes()), &verified, &stderr); err != nil {
		t.Fatal(err)
	}

	var report struct {
		Status, Trust string
		References    []string
	}
	if err := json.Unmarshal(verificationDetails(t, verified.Bytes()), &report); err != nil {
		t.Fatal(err)
	}

	if report.Status != statusValid || report.Trust != "externally-supplied-key" || len(report.References) != 1 {
		t.Fatal(verified.String())
	}

	var canonical bytes.Buffer
	if err := run(context.Background(), []string{nameC14n}, strings.NewReader(`<r b="2" a="1"/>`), &canonical, &stderr); err != nil {
		t.Fatal(err)
	}

	if canonical.String() != `<r a="1" b="2"></r>` {
		t.Fatal(canonical.String())
	}

	output := filepath.Join(dir, "out.xml")
	if err := run(context.Background(), []string{nameSign, flagKey, private, "-out", output}, strings.NewReader(source), &signed, &stderr); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(output); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRejects(t *testing.T) {
	for _, args := range [][]string{{nameBogus}, {nameSign}, {nameVerify}, {nameSign, flagKey, "-"}, {nameC14n, "unexpected"}, {nameC14n, "-id", "missing"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errout bytes.Buffer
			if err := run(context.Background(), args, strings.NewReader(`<r/>`), &out, &errout); err == nil {
				t.Fatal("accepted invalid invocation")
			}
		})
	}
}

func TestCLICanonicalAlgorithms(t *testing.T) {
	for _, alg := range []string{c14n.Canonical10, c14n.Canonical11, c14n.Exclusive} {
		t.Run(alg, func(t *testing.T) {
			var out, errout bytes.Buffer
			if err := run(context.Background(), []string{nameC14n, "-algorithm", alg},
				strings.NewReader(`<r xmlns:p="urn:p"><c/></r>`), &out, &errout); err != nil {
				t.Fatal(err)
			}

			want := `<r xmlns:p="urn:p"><c></c></r>`
			if alg == c14n.Exclusive {
				want = `<r><c></c></r>`
			}

			if out.String() != want {
				t.Fatalf("got %q, want %q", out.String(), want)
			}
		})
	}

	var out, errout bytes.Buffer
	if err := run(context.Background(), []string{nameC14n, "-algorithm", nameUnknown},
		strings.NewReader(`<r/>`), &out, &errout); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
}

func BenchmarkVerify(b *testing.B) {
	c := testcert.New(b)

	d, err := document.Parse(b.Context(), []byte(`<r ID="root"><v>value</v></r>`), document.DefaultLimits())
	if err != nil {
		b.Fatal(err)
	}

	d, err = xmldsig.SignEnveloped(context.Background(), d, c.LeafKey, xmldsig.SignOptions{SignatureMethod: xmldsig.ECDSASHA256})
	if err != nil {
		b.Fatal(err)
	}

	raw, err := d.XML(b.Context())
	if err != nil {
		b.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(c.LeafKey.Public())
	if err != nil {
		b.Fatal(err)
	}

	path := filepath.Join(b.TempDir(), "public.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: publicKeyPEMType, Bytes: der}), 0o600); err != nil {
		b.Fatal(err)
	}

	args := []string{nameVerify, flagKey, path, "-root-local", "r"}

	b.ReportAllocs()

	for b.Loop() {
		if err := run(context.Background(), args, bytes.NewReader(raw), io.Discard, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}
