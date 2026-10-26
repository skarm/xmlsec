package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/binding"
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
	if err := run(t.Context(), []string{nameSign, flagKey, private}, strings.NewReader(source), &signed, &stderr); err != nil {
		t.Fatal(err)
	}

	var verified bytes.Buffer
	if err := run(t.Context(), []string{nameVerify, flagKey, public, "-root-local", "r"}, bytes.NewReader(signed.Bytes()), &verified, &stderr); err != nil {
		t.Fatal(err)
	}

	var report struct {
		Status     string
		Trust      string
		References []string
	}
	if err := json.Unmarshal(verificationDetails(t, verified.Bytes()), &report); err != nil {
		t.Fatal(err)
	}

	if report.Status != statusValid || report.Trust != "externally-supplied-key" || len(report.References) != 1 {
		t.Fatal(verified.String())
	}

	var canonical bytes.Buffer
	if err := run(t.Context(), []string{nameC14n}, strings.NewReader(`<r b="2" a="1"/>`), &canonical, &stderr); err != nil {
		t.Fatal(err)
	}

	if canonical.String() != `<r a="1" b="2"></r>` {
		t.Fatal(canonical.String())
	}

	output := filepath.Join(dir, "out.xml")
	if err := run(t.Context(), []string{nameSign, flagKey, private, "-out", output}, strings.NewReader(source), &signed, &stderr); err != nil {
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
			if err := run(t.Context(), args, strings.NewReader(`<r/>`), &out, &errout); err == nil {
				t.Fatal("accepted invalid invocation")
			}
		})
	}
}

func TestCLICanonicalAlgorithms(t *testing.T) {
	for _, alg := range []string{c14n.Canonical10, c14n.Canonical11, c14n.Exclusive} {
		t.Run(alg, func(t *testing.T) {
			var out, errout bytes.Buffer
			if err := run(t.Context(), []string{nameC14n, "-algorithm", alg},
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
	if err := run(t.Context(), []string{nameC14n, "-algorithm", nameUnknown},
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

	d, err = xmldsig.SignEnveloped(b.Context(), d, c.LeafKey, xmldsig.SignOptions{SignatureMethod: xmldsig.ECDSASHA256})
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
		if err := run(b.Context(), args, bytes.NewReader(raw), io.Discard, io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDocumentIO(b *testing.B) {
	for _, size := range []int{16 << 10, 1 << 20} {
		raw := []byte("<root>" + strings.Repeat("a", size) + "</root>")
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.Run("Read", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for b.Loop() {
					if _, err := readDocument(b.Context(), "-", bytes.NewReader(raw)); err != nil {
						b.Fatal(err)
					}
				}
			})
			doc, err := document.Parse(b.Context(), raw, document.DefaultLimits())
			if err != nil {
				b.Fatal(err)
			}
			path := filepath.Join(b.TempDir(), "out.xml")
			b.Run("FileWrite", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for b.Loop() {
					if err := documentOutput(b.Context(), path, io.Discard, doc); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkDetachedCMSCLI(b *testing.B) {
	c := testcert.New(b)
	key, err := x509.MarshalPKCS8PrivateKey(c.LeafKey)
	if err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir()
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.der")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: key}), 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(certPath, c.Leaf.Raw, 0o600); err != nil {
		b.Fatal(err)
	}
	args := []string{"cms", "sign", "-detached", "-key", keyPath, "-certificate", certPath}
	for _, size := range []int{16 << 10, 1 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			raw := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if err := run(b.Context(), args, bytes.NewReader(raw), io.Discard, io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTimestampRequestCLI(b *testing.B) {
	for _, size := range []int{256, 16 << 10, 8 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			raw := make([]byte, size)
			args := []string{"timestamp", "request", "-omit-nonce"}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if err := run(b.Context(), args, bytes.NewReader(raw), io.Discard, io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCLIOutputStrategies(b *testing.B) {
	for _, size := range []int{256, 16 << 10, 1 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			doc, err := document.Parse(b.Context(), []byte("<r>"+strings.Repeat("x", size)+"</r>"), document.DefaultLimits())
			if err != nil {
				b.Fatal(err)
			}
			value := map[string]any{"data": strings.Repeat("<&é", size/4)}
			for _, kind := range []string{"JSON", "POST", "XMLPreflight"} {
				for _, streamed := range []bool{false, true} {
					b.Run(fmt.Sprintf("%s/Stream=%v", kind, streamed), func(b *testing.B) {
						path := filepath.Join(b.TempDir(), "out")
						b.ReportAllocs()
						for b.Loop() {
							var err error
							switch kind {
							case "JSON":
								if streamed {
									err = jsonOutput(b.Context(), path, io.Discard, value)
								} else {
									var output bytes.Buffer
									err = writeJSON(&output, value)
									if err == nil {
										err = writeOutputContext(b.Context(), path, io.Discard, output.Bytes())
									}
								}
							case "POST":
								if streamed {
									err = produceOutput(b.Context(), path, io.Discard, func(dst io.Writer) error {
										_, err := binding.WritePOST(b.Context(), dst, doc, binding.Request, nil, binding.POSTLimits{MaxXMLBytes: 2 << 20, MaxFormBytes: 4 << 20})
										return err
									})
								} else {
									var raw []byte
									raw, err = binding.EncodePOST(b.Context(), doc, binding.Request, nil, binding.POSTLimits{MaxXMLBytes: 2 << 20, MaxFormBytes: 4 << 20})
									if err == nil {
										err = writeOutputContext(b.Context(), path, io.Discard, raw)
									}
								}
							case "XMLPreflight":
								if streamed {
									_, err = doc.WriteXML(b.Context(), io.Discard, execution(b.Context()).output)
									if err == nil {
										err = documentOutput(b.Context(), path, io.Discard, doc)
									}
								} else {
									var raw []byte
									raw, err = doc.XML(b.Context())
									if err == nil {
										err = writeOutputContext(b.Context(), path, io.Discard, raw)
									}
								}
							}
							if err != nil {
								b.Fatal(err)
							}
						}
					})
				}
			}
		})
	}
}
