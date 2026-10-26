package binding_test

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/xmldsig"
)

const request = `<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="request" Version="2.0" IssueInstant="2026-10-08T00:00:00Z"/>`

func TestRedirectRoundTripAndRawEncoding(t *testing.T) {
	ctx := t.Context()

	k := key(t)
	for _, relay := range []*string{nil, new(string), func() *string { s := "opaque & state+é"; return &s }()} {
		raw, e := binding.SignRedirect(ctx, doc(t, request), binding.Request, relay, k, options())
		if e != nil {
			t.Fatal(e)
		}

		r, e := binding.VerifyRedirect(ctx, raw, k.Public(), options())
		if e != nil {
			t.Fatal(e)
		}

		value, ok := r.RelayState()
		if ok != (relay != nil) || (relay != nil && value != *relay) {
			t.Fatal("RelayState presence/value lost")
		}

		altered := strings.Replace(raw, "%3A", "%3a", 1)
		if _, e = binding.VerifyRedirect(ctx, altered, k.Public(), options()); !errors.Is(e, xmldsig.ErrSignature) {
			t.Fatalf("re-encoded query accepted: %v", e)
		}
		// Sign a valid noncanonical encoding to prove verification uses received
		// raw values, not the library's preferred URL encoder.
		base, _, _ := strings.Cut(altered, "&Signature=")

		sig, e := xmldsig.SignMessage(ctx, []byte(base), k, xmldsig.ECDSASHA256, xmldsig.Policy{})
		if e != nil {
			t.Fatal(e)
		}

		if _, e = binding.VerifyRedirect(ctx, base+"&Signature="+url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), k.Public(), options()); e != nil {
			t.Fatal(e)
		}
	}
}

func TestRedirectRejectsAmbiguity(t *testing.T) {
	ctx := t.Context()
	k := key(t)

	raw, e := binding.SignRedirect(ctx, doc(t, request), binding.Request, nil, k, options())
	if e != nil {
		t.Fatal(e)
	}

	for _, bad := range []string{raw + "&SigAlg=x", raw + "&SAMLResponse=x", raw + "&RelayState=a&RelayState=b", strings.Replace(raw, "SAMLRequest", "SAML%52equest", 1), raw + "&x=%zz", raw + ";x=1", raw + "&Signature=x"} {
		if _, e = binding.VerifyRedirect(ctx, bad, k.Public(), options()); e == nil {
			t.Fatal("ambiguous query accepted")
		}
	}

	long := strings.Repeat("é", 41)
	if _, e = binding.SignRedirect(ctx, doc(t, request), binding.Request, &long, k, options()); !errors.Is(e, binding.ErrPolicy) {
		t.Fatal("RelayState limit counted runes instead of bytes")
	}
}

func TestRedirectAuthenticatesBeforeDecodeAndBoundsInflation(t *testing.T) {
	ctx := t.Context()
	k := key(t)

	raw := "SAMLRequest=not-base64&SigAlg=" + url.QueryEscape(xmldsig.ECDSASHA256) + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(make([]byte, 64)))
	if _, e := binding.VerifyRedirect(ctx, raw, k.Public(), options()); !errors.Is(e, xmldsig.ErrSignature) {
		t.Fatalf("processed message before authentication: %v", e)
	}

	text := strings.Replace(request, "/>", ">"+strings.Repeat(" ", 5000)+"</p:AuthnRequest>", 1)

	q, e := binding.SignRedirect(ctx, doc(t, text), binding.Request, nil, k, options())
	if e != nil {
		t.Fatal(e)
	}

	small := options()

	small.MaxMessageBytes = 128
	if _, e = binding.VerifyRedirect(ctx, q, k.Public(), small); !errors.Is(e, binding.ErrPolicy) {
		t.Fatalf("inflate budget: %v", e)
	}
}

func TestRedirectRemovesOnlyProtocolSignature(t *testing.T) {
	ctx := t.Context()
	k := key(t)
	source := `<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/><nested><ds:Signature/></nested></p:Response>`
	d := doc(t, source)
	before, _ := d.XML(ctx)

	raw, e := binding.SignRedirect(ctx, d, binding.Response, nil, k, options())
	if e != nil {
		t.Fatal(e)
	}

	result, e := binding.VerifyRedirect(ctx, raw, k.Public(), options())
	if e != nil {
		t.Fatal(e)
	}

	after, _ := d.XML(ctx)
	if string(before) != string(after) {
		t.Fatal("source modified")
	}

	if len(xmldsig.Signatures(result.Document())) != 1 {
		t.Fatal("nested Signature removed")
	}
}

func FuzzVerifyRedirect(f *testing.F) {
	rawKey, err := os.ReadFile("../../testdata/next/ec256.pub.pem")
	if err != nil {
		f.Fatal(err)
	}

	block, _ := pem.Decode(rawKey)
	if block == nil {
		f.Fatal("missing PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		f.Fatal(err)
	}

	seed, err := os.ReadFile("../../testdata/next/ec256.redirect.python.txt")
	if err != nil {
		f.Fatal(err)
	}

	opt := binding.Options{MaxQueryBytes: 4096, MaxMessageBytes: 4096}
	if _, err = binding.VerifyRedirect(f.Context(), string(seed), key, opt); err != nil {
		f.Fatalf("invalid fixed seed: %v", err)
	}

	f.Add(string(seed))
	f.Add("SAMLRequest=x&SigAlg=x&Signature=x")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}

		_, _ = binding.VerifyRedirect(t.Context(), s, key, opt)
	})
}

func BenchmarkVerifyRedirect(b *testing.B) {
	k := key(b)

	raw, err := binding.SignRedirect(b.Context(), doc(b, request), binding.Request, nil, k, options())
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := binding.VerifyRedirect(b.Context(), raw, k.Public(), options()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRedirectRejectsAuthenticatedTrailingData(t *testing.T) {
	k := key(t)

	var compressed bytes.Buffer

	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.WriteString(writer, request); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	valid := base64.StdEncoding.EncodeToString(compressed.Bytes())
	for _, tc := range []struct {
		name    string
		message string
		valid   bool
	}{
		{"valid", valid, true},
		{"trailing compressed byte", base64.StdEncoding.EncodeToString(append(bytes.Clone(compressed.Bytes()), 0)), false},
		{"truncated compressed data", base64.StdEncoding.EncodeToString(compressed.Bytes()[:compressed.Len()-1]), false},
		{"second Base64 block", valid + "AA==", false},
		{"extra padding", valid + "=", false},
		{"whitespace", valid + "\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := "SAMLRequest=" + url.QueryEscape(tc.message) + "&SigAlg=" + url.QueryEscape(xmldsig.ECDSASHA256)

			signature, err := xmldsig.SignMessageReader(t.Context(), strings.NewReader(input), k, xmldsig.ECDSASHA256, xmldsig.Policy{})
			if err != nil {
				t.Fatal(err)
			}

			query := input + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))

			result, err := binding.VerifyRedirect(t.Context(), query, k.Public(), options())
			if tc.valid {
				if err != nil || result == nil {
					t.Fatal(err)
				}
			} else if result != nil || err == nil || errors.Is(err, xmldsig.ErrSignature) {
				t.Fatal("authenticated malformed message was accepted or lost signature verification", result, err)
			}
		})
	}
}

func key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func doc(t testing.TB, text string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(text), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func options() binding.Options { return binding.Options{SignatureMethod: xmldsig.ECDSASHA256} }

// BenchmarkSignRedirect measures the complete public binding, including XML
// output, raw DEFLATE, URL encoding and signing, on a reusable snapshot/key.
func BenchmarkSignRedirect(b *testing.B) {
	k := key(b)
	d := doc(b, request)
	b.Run("Serial", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := binding.SignRedirect(b.Context(), d, binding.Request, nil, k, options()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := binding.SignRedirect(b.Context(), d, binding.Request, nil, k, options()); err != nil {
					b.Error(err)
				}
			}
		})
	})
}

func TestRedirectCompressionReuse(t *testing.T) {
	t.Parallel()

	k := key(t)
	for _, size := range []int{0, 4097, 1 << 20, 1, 128} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			d := doc(t, strings.Replace(request, "/>", ">"+strings.Repeat("abcde", size/5)+strings.Repeat("x", size%5)+"</p:AuthnRequest>", 1))
			limited := options()
			limited.MaxCompressedBytes = 1
			if _, err := binding.SignRedirect(t.Context(), d, binding.Request, nil, k, limited); !errors.Is(err, binding.ErrPolicy) {
				t.Fatal("compressed limit lost", err)
			}
			for range 3 {
				query, err := binding.SignRedirect(t.Context(), d, binding.Request, nil, k, options())
				if err != nil {
					t.Fatal(err)
				}
				result, err := binding.VerifyRedirect(t.Context(), query, k.Public(), options())
				if err != nil || result.Document().Root().Text() != d.Root().Text() {
					t.Fatal("independent stream/round trip lost", err)
				}
				var expected bytes.Buffer
				fresh, err := flate.NewWriter(&expected, flate.DefaultCompression)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := d.WriteXML(t.Context(), fresh, 2<<20); err != nil {
					t.Fatal(err)
				}
				if err := fresh.Close(); err != nil {
					t.Fatal(err)
				}
				values, err := url.ParseQuery(query)
				if err != nil || values.Get("SAMLRequest") != base64.StdEncoding.EncodeToString(expected.Bytes()) {
					t.Fatal("reused compression differs from a fresh stream", err)
				}
			}
		})
	}
}
