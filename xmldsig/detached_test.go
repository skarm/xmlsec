package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/transform"
	"github.com/skarm/xmlsec/xmldsig"
)

const (
	programFirstURI  = "urn:first"
	programSecondURI = "urn:second"
	uriUrnXML        = "urn:xml"
	nameBad          = "bad"
	nameEmptyDat     = "empty.dat"
	uriUrnA          = "urn:a"
	uriUrnB          = "urn:b"
	uriUrnBinary     = "urn:binary"
)

func TestDetachedAlgorithmsAndTransforms(t *testing.T) {
	keyRSA := rsaKey(t)

	_, keyEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keys := []struct {
		name   string
		method string
		key    crypto.Signer
	}{
		{"RSA256", xmldsig.RSASHA256, keyRSA},
		{"RSA384", xmldsig.RSASHA384, keyRSA},
		{"RSA512", xmldsig.RSASHA512, keyRSA},
		{"EC256", xmldsig.ECDSASHA256, ecKey(t, elliptic.P256())},
		{"EC384", xmldsig.ECDSASHA384, ecKey(t, elliptic.P384())},
		{"EC521", xmldsig.ECDSASHA512, ecKey(t, elliptic.P521())},
		{"Ed25519", xmldsig.Ed25519, keyEd},
		{"Ed25519ph", xmldsig.Ed25519ph, keyEd},
	}
	raw := []byte{0, 255, 10, 11, 22}
	encodedXML := []byte(base64.StdEncoding.EncodeToString([]byte(`<r z="2" a="1"><!--comment--><x>text</x></r>`)))
	resources := map[string][]byte{uriUrnBinary: raw, uriUrnXML: encodedXML, nameEmptyDat: {}}
	refs := []xmldsig.DetachedReference{
		{URI: uriUrnBinary, Type: "urn:example:binary"},
		{URI: uriUrnXML, DigestMethod: xmldsig.SHA512, Transforms: []reference.Transform{{Algorithm: reference.Base64}, {Algorithm: c14n.Canonical11WithComments}}},
		{URI: nameEmptyDat, DigestMethod: xmldsig.SHA384},
	}
	expected := []string{nameEmptyDat, uriUrnXML, uriUrnBinary}
	cms := []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments}

	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			testDetachedAlgorithmsAndTransformsCase(t, &cms, &k, &refs, &resources, &expected, &raw)
		})
	}
}

func testDetachedAlgorithmsAndTransformsCase(t *testing.T, cms *[]string, k *struct {
	name   string
	method string
	key    crypto.Signer
}, refs *[]xmldsig.DetachedReference, resources *map[string][]byte, expected *[]string, raw *[]byte,
) {
	for _, cm := range *cms {
		t.Run(cm, func(t *testing.T) {
			sig := signDetached(t, k.key, *refs, sourceMap(*resources), xmldsig.DetachedSignOptions{SignatureMethod: k.method, Canonicalization: reference.Transform{Algorithm: cm}, Policy: xmldsig.ModernPolicy()})

			result, err := xmldsig.VerifyDetached(context.Background(), sig, k.key.Public(), sourceMap(*resources), xmldsig.DetachedVerifyOptions{ExpectedURIs: *expected, AllowedCanonicalizationMethods: []string{cm}, Policy: xmldsig.ModernPolicy()})
			if err != nil {
				t.Fatal(err)
			}

			if result.SignatureMethod() != k.method || len(result.KeyFingerprintSHA256()) != 64 || len(result.References()) != 3 {
				t.Fatal("bad result metadata")
			}

			checked := result.References()
			if checked[0].Target().Valid() || checked[0].IsCanonicalXML() || checked[0].Type() != "urn:example:binary" || !bytes.Equal(digestInput(t, checked[0]), *raw) {
				t.Fatal("raw reference metadata")
			}

			if !checked[1].IsCanonicalXML() || string(digestInput(t, checked[1])) != `<r a="1" z="2"><!--comment--><x>text</x></r>` || len(checked[1].Steps()) != 3 {
				t.Fatal(string(digestInput(t, checked[1])), checked[1].Steps())
			}

			if checked[1].InputKind() != reference.OctetStream || checked[2].DigestMethod() != xmldsig.SHA384 || len(digestInput(t, checked[2])) != 0 {
				t.Fatal("bad digest metadata")
			}

			digestInput(t, checked[0])[0] = 44
			checked[1].Transforms()[0].Algorithm = nameBad

			checked[1].Steps()[0].Algorithm = nameBad
			if digestInput(t, checked[0])[0] != 0 || checked[1].Transforms()[0].Algorithm == nameBad || checked[1].Steps()[0].Algorithm == nameBad {
				t.Fatal("mutable result")
			}
			// The root-enveloped profile rejects a standalone detached signature.
			if result, err := xmldsig.Verify(context.Background(), sig, k.key.Public(), xmldsig.VerifyOptions{}); result != nil || !errors.Is(err, xmldsig.ErrStructure) {
				t.Fatal(result, err)
			}
		})
	}
}

func TestDetachedPreauthenticationAndExactSet(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	resources := map[string][]byte{uriUrnA: []byte("a"), uriUrnB: []byte("b")}
	refs := []xmldsig.DetachedReference{{URI: uriUrnA}, {URI: uriUrnB, Transforms: []reference.Transform{{Algorithm: reference.Base64}}}}
	// b's source is valid base64 (not the literal value above).
	resources[uriUrnB] = []byte("Yg==")
	sig := signDetached(t, key, refs, sourceMap(resources), xmldsig.DetachedSignOptions{})
	source := xmlString(t, sig)
	wrong := ecKey(t, elliptic.P256())

	cases := []struct {
		name string
		key  crypto.PublicKey
		xml  string
		opt  xmldsig.DetachedVerifyOptions
		want error
	}{
		{"wrong key", wrong.Public(), source, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}}, xmldsig.ErrSignature},
		{"no expected set", key.Public(), source, xmldsig.DetachedVerifyOptions{}, xmldsig.ErrPolicy},
		{"subset", key.Public(), source, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA}}, xmldsig.ErrPolicy},
		{"superset", key.Public(), source, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB, "urn:c"}}, xmldsig.ErrPolicy},
		{"different set", key.Public(), source, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, "urn:c"}}, xmldsig.ErrPolicy},
		{"duplicate expected", key.Public(), source, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnA}}, xmldsig.ErrPolicy},
		{"unknown last transform", key.Public(), strings.Replace(source, reference.Base64, "urn:unknown", 1), xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}}, xmldsig.ErrAlgorithm},
		{"disallowed transform", key.Public(), source, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}, Processing: reference.Options{AllowedTransforms: []string{c14n.Exclusive}}}, xmldsig.ErrPolicy},
		{"duplicate reference", key.Public(), strings.Replace(source, `URI="urn:b"`, `URI="urn:a"`, 1), xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}}, xmldsig.ErrReference},
		{"external fragment", key.Public(), strings.Replace(source, `URI="urn:b"`, `URI="urn:b#x"`, 1), xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}}, xmldsig.ErrReference},
		{"missing URI", key.Public(), strings.Replace(source, ` URI="urn:b"`, "", 1), xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}}, xmldsig.ErrStructure},
		{"enveloped on external", key.Public(), strings.Replace(source, reference.Base64, reference.EnvelopedSignature, 1), xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}}, xmldsig.ErrPolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { calls++; return nil, errors.New("must not run") })

			result, err := xmldsig.VerifyDetached(context.Background(), parse(t, tc.xml), tc.key, resolver, tc.opt)
			if result != nil || !errors.Is(err, tc.want) || calls != 0 {
				t.Fatalf("result=%v err=%v calls=%d", result, err, calls)
			}
		})
	}

	t.Run("new canonicalization requires explicit permission", func(t *testing.T) {
		sig := signDetached(t, key, []xmldsig.DetachedReference{{URI: uriUrnA}}, sourceMap(resources), xmldsig.DetachedSignOptions{Canonicalization: reference.Transform{Algorithm: c14n.Canonical11}})
		calls := 0
		resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { calls++; return nil, nil })

		out, err := xmldsig.VerifyDetached(context.Background(), sig, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA}})
		if out != nil || !errors.Is(err, xmldsig.ErrPolicy) || calls != 0 {
			t.Fatal(out, err, calls)
		}
	})
}

func TestDetachedEveryDigestAndTypedError(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	resources := map[string][]byte{uriUrnA: []byte("first"), uriUrnB: []byte("second")}
	refs := []xmldsig.DetachedReference{{URI: uriUrnA}, {URI: uriUrnB}}
	sig := signDetached(t, key, refs, sourceMap(resources), xmldsig.DetachedSignOptions{})
	corrupted := wrongSecondDigest(t, sig, key)
	calls := 0
	resolver := xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		calls++
		return sourceMap(resources).Resolve(ctx, uri)
	})
	out, err := xmldsig.VerifyDetached(context.Background(), corrupted, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}})

	var detail *xmldsig.ReferenceError
	if out != nil || !errors.Is(err, xmldsig.ErrDigest) || !errors.As(err, &detail) || detail.Index != 1 || detail.URI != uriUrnB || detail.Stage != "digest" || calls != 2 {
		t.Fatal(out, err, calls)
	}

	resources[uriUrnB] = []byte("changed")

	out, err = xmldsig.VerifyDetached(context.Background(), sig, key.Public(), sourceMap(resources), xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}})
	if out != nil || !errors.Is(err, xmldsig.ErrDigest) {
		t.Fatal(out, err)
	}
}

// Replace the second digest then independently recompute the SignedInfo ECDSA
// signature with stdlib. This proves the verifier checks the second Reference,
// rather than rejecting solely due to a corrupted SignatureValue.
func wrongSecondDigest(t testing.TB, doc *document.Document, key *ecdsa.PrivateKey) *document.Document {
	t.Helper()
	src := xmlString(t, doc)
	open, closer := "<ds:DigestValue>", "</ds:DigestValue>"
	first := strings.Index(src, open) + len(open)
	second := strings.Index(src[first:], open) + first + len(open)
	end := strings.Index(src[second:], closer) + second
	src = src[:second] + base64.StdEncoding.EncodeToString(make([]byte, 32)) + src[end:]
	changed := parse(t, src)
	si := changed.Root().Children()[0]

	var canonical bytes.Buffer
	if err := c14n.WriteElement(context.Background(), &canonical, si, c14n.Options{}); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(canonical.Bytes())

	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	var rs struct {
		R *big.Int
		S *big.Int
	}
	if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}

	value := make([]byte, 64)
	rs.R.FillBytes(value[:32])
	rs.S.FillBytes(value[32:])

	start := strings.Index(src, "<ds:SignatureValue>") + len("<ds:SignatureValue>")
	end = strings.Index(src[start:], "</ds:SignatureValue>") + start

	return parse(t, src[:start]+base64.StdEncoding.EncodeToString(value)+src[end:])
}

func TestDetachedResourceLimitsAndCleanup(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	refs := []xmldsig.DetachedReference{{URI: uriUrnA}}
	sig := signDetached(t, key, refs, sourceMap(map[string][]byte{uriUrnA: []byte("abc")}), xmldsig.DetachedSignOptions{})
	readErr := errors.New("read failed")
	closeErr := errors.New("close failed")
	resolveErr := errors.New("resolver failed")

	cases := []struct {
		name       string
		reader     io.Reader
		closeErr   error
		resolveErr error
		limits     xmldsig.ResourceLimits
		want       error
	}{
		{name: "exact limit", reader: strings.NewReader("abc"), limits: xmldsig.ResourceLimits{MaxResourceBytes: 3}},
		{name: "one past limit", reader: strings.NewReader("abcd"), limits: xmldsig.ResourceLimits{MaxResourceBytes: 3}, want: xmldsig.ErrPolicy},
		{name: "read error", reader: errorReader{readErr}, want: readErr},
		{name: "close error", reader: strings.NewReader("abc"), closeErr: closeErr, want: closeErr},
		{name: "reader with resolver error", reader: strings.NewReader("abc"), resolveErr: resolveErr, want: resolveErr},
		{name: "no progress", reader: stuckReader{}, want: io.ErrNoProgress},
		{name: "bad reader count", reader: badCountReader{}, want: xmldsig.ErrReference},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observed := &observedReader{Reader: tc.reader, closeErr: tc.closeErr}
			resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { return observed, tc.resolveErr })

			out, err := xmldsig.VerifyDetached(context.Background(), sig, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA}, Limits: tc.limits})
			if tc.want == nil {
				if err != nil || out == nil {
					t.Fatal(out, err)
				}
			} else if out != nil || !errors.Is(err, tc.want) {
				t.Fatal(out, err)
			}

			if observed.closes != 1 {
				t.Fatal("reader not closed exactly once", observed.closes)
			}

			if tc.resolveErr != nil && observed.reads != 0 {
				t.Fatal("read after resolver error")
			}
		})
	}

	t.Run("total limit", func(t *testing.T) {
		refs := []xmldsig.DetachedReference{{URI: uriUrnA}, {URI: uriUrnB}}
		src := sourceMap(map[string][]byte{uriUrnA: []byte("abc"), uriUrnB: []byte("def")})

		sig := signDetached(t, key, refs, src, xmldsig.DetachedSignOptions{})
		if out, err := xmldsig.VerifyDetached(context.Background(), sig, key.Public(), src, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA, uriUrnB}, Limits: xmldsig.ResourceLimits{MaxTotalResourceBytes: 5}}); out != nil || !errors.Is(err, xmldsig.ErrPolicy) {
			t.Fatal(out, err)
		}

		if out, err := xmldsig.SignDetached(context.Background(), refs, key, src, xmldsig.DetachedSignOptions{Limits: xmldsig.ResourceLimits{MaxTotalResourceBytes: 5}}); out != nil || !errors.Is(err, xmldsig.ErrPolicy) {
			t.Fatal(out, err)
		}
	})
	t.Run("nil reader", func(t *testing.T) {
		resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { var r *observedReader; return r, nil })

		out, err := xmldsig.VerifyDetached(context.Background(), sig, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA}})
		if out != nil || !errors.Is(err, xmldsig.ErrReference) {
			t.Fatal(out, err)
		}
	})
	t.Run("cancel after resolver returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		r := &observedReader{Reader: strings.NewReader("abc")}
		resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { cancel(); return r, nil })

		out, err := xmldsig.VerifyDetached(ctx, sig, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA}})
		if out != nil || !errors.Is(err, context.Canceled) || r.closes != 1 || r.reads != 0 {
			t.Fatal(out, err, r.closes, r.reads)
		}
	})
}

func TestDetachedValidationBeforeSigningIO(t *testing.T) {
	key := ecKey(t, elliptic.P256())

	cases := append(make([]struct {
		name string
		refs []xmldsig.DetachedReference
		opt  xmldsig.DetachedSignOptions
	}, 0, 15), []struct {
		name string
		refs []xmldsig.DetachedReference
		opt  xmldsig.DetachedSignOptions
	}{
		{"no refs", nil, xmldsig.DetachedSignOptions{}},
		{"duplicate", []xmldsig.DetachedReference{{URI: uriUrnA}, {URI: uriUrnA}}, xmldsig.DetachedSignOptions{}},
		{"unknown last", []xmldsig.DetachedReference{{URI: uriUrnA}, {URI: uriUrnB, Transforms: []reference.Transform{{Algorithm: nameBad}}}}, xmldsig.DetachedSignOptions{}},
		{"enveloped", []xmldsig.DetachedReference{{URI: uriUrnA, Transforms: []reference.Transform{{Algorithm: reference.EnvelopedSignature}}}}, xmldsig.DetachedSignOptions{}},
		{"bad method", []xmldsig.DetachedReference{{URI: uriUrnA}}, xmldsig.DetachedSignOptions{SignatureMethod: xmldsig.RSASHA256}},
		{"negative limits", []xmldsig.DetachedReference{{URI: uriUrnA}}, xmldsig.DetachedSignOptions{Limits: xmldsig.ResourceLimits{MaxResourceBytes: -1}}},
		{"bad c14n", []xmldsig.DetachedReference{{URI: uriUrnA}}, xmldsig.DetachedSignOptions{Canonicalization: reference.Transform{Algorithm: nameBad}}},
		{"bad Type char", []xmldsig.DetachedReference{{URI: uriUrnA, Type: "\x00"}}, xmldsig.DetachedSignOptions{}},
	}...)
	for _, uri := range []string{"", "#id", "http://example.invalid/a#id", "has space", "has\\slash", "bad%escape", "\x00uri"} {
		cases = append(cases, struct {
			name string
			refs []xmldsig.DetachedReference
			opt  xmldsig.DetachedSignOptions
		}{"URI-" + uri, []xmldsig.DetachedReference{{URI: uri}}, xmldsig.DetachedSignOptions{}})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) { calls++; return nil, errors.New("called") })

			out, err := xmldsig.SignDetached(context.Background(), tc.refs, key, resolver, tc.opt)
			if out != nil || err == nil || calls != 0 {
				t.Fatal(out, err, calls)
			}
		})
	}
}

func TestDetachedByteBudgetAndExternalSigner(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	adapter := &controlledSigner{Signer: key}
	refs := []xmldsig.DetachedReference{{URI: uriUrnA}}
	resolver := sourceMap(map[string][]byte{uriUrnA: []byte("abc")})

	sig := signDetached(t, adapter, refs, resolver, xmldsig.DetachedSignOptions{})
	if adapter.calls != 1 {
		t.Fatal(adapter.calls)
	}

	var si bytes.Buffer
	if err := c14n.WriteElement(context.Background(), &si, sig.Root().Children()[0], c14n.Options{}); err != nil {
		t.Fatal(err)
	}

	total := si.Len() + 3
	for _, size := range []int{total, total - 1} {
		result, err := xmldsig.VerifyDetached(context.Background(), sig, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA}, Policy: xmldsig.Policy{MaxCanonicalBytes: size}})

		doc, signErr := xmldsig.SignDetached(context.Background(), refs, key, resolver, xmldsig.DetachedSignOptions{Policy: xmldsig.Policy{MaxCanonicalBytes: size}})
		if size == total {
			if err != nil || signErr != nil {
				t.Fatal(err, signErr)
			}
		} else if result != nil || doc != nil || err == nil || signErr == nil {
			t.Fatal(result, doc, err, signErr)
		}
	}
}

func TestDetachedConcurrencyAndZeroValues(t *testing.T) {
	key := ecKey(t, elliptic.P256())
	resolver := sourceMap(map[string][]byte{uriUrnA: []byte("abc")})
	refs := []xmldsig.DetachedReference{{URI: uriUrnA}}
	sig := signDetached(t, key, refs, resolver, xmldsig.DetachedSignOptions{})

	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if _, err := xmldsig.VerifyDetached(context.Background(), sig, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnA}}); err != nil {
				t.Error(err)
			}
		})
	}

	wg.Wait()

	if out, err := xmldsig.SignDetached(nil, refs, key, resolver, xmldsig.DetachedSignOptions{}); out != nil || err == nil {
		t.Fatal(out, err)
	}

	if out, err := xmldsig.VerifyDetached(nil, sig, key.Public(), resolver, xmldsig.DetachedVerifyOptions{}); out != nil || err == nil {
		t.Fatal(out, err)
	}

	var fn xmldsig.ResolverFunc
	if out, err := xmldsig.SignDetached(context.Background(), refs, key, fn, xmldsig.DetachedSignOptions{}); out != nil || err == nil {
		t.Fatal(out, err)
	}

	if out, err := xmldsig.VerifyDetached(context.Background(), nil, key.Public(), resolver, xmldsig.DetachedVerifyOptions{}); out != nil || err == nil {
		t.Fatal(out, err)
	}

	var r *xmldsig.DetachedResult
	if r.SignatureMethod() != "" || r.KeyFingerprintSHA256() != "" || r.References() != nil {
		t.Fatal("nonzero result")
	}

	var rr xmldsig.ReferenceResult
	if rr.Digest() != nil || rr.Size() != 0 || rr.IsCanonicalXML() || rr.InputKind() != reference.Invalid || rr.Steps() != nil {
		t.Fatal("nonzero reference")
	}
}

func TestDetachedProgramPreflight(t *testing.T) {
	approved := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: programTrueXPath, Namespaces: map[string]string{"ds": xmldsig.Namespace}}}}

	e, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{approved}})
	if err != nil {
		t.Fatal(err)
	}

	processing := reference.DefaultOptions()
	processing.Extension = e

	processing.AllowedTransforms = append(processing.AllowedTransforms, reference.XPath, reference.XPathFilter2, reference.XSLT)
	for _, tt := range []struct {
		name    string
		program reference.Transform
		deny    bool
	}{
		{"unapproved", reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "false()", Namespaces: map[string]string{"ds": xmldsig.Namespace}}}}, false},
		{"unapproved context", reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: programTrueXPath, Namespaces: map[string]string{"ds": xmldsig.Namespace, "p": "urn:extra"}}}}, false},
		{"missing expression", reference.Transform{Algorithm: reference.XPath}, false},
		{"bad Filter2", reference.Transform{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{{Expression: "/", Filter: "replace"}}}, false},
		{"reserved prefix", reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: programTrueXPath, Namespaces: map[string]string{"ds": "urn:wrong"}}}}, false},
		{"malformed stylesheet", reference.Transform{Algorithm: reference.XSLT, Stylesheet: []byte(`<broken>`)}, false},
		{"unknown", reference.Transform{Algorithm: "urn:unknown"}, false},
		{"forbidden", approved, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				calls++
				return nil, errors.New("unexpected resolver call")
			})
			signer := &coreCountSigner{Signer: coreEC(t)}

			options := processing
			if tt.deny {
				options = reference.DefaultOptions()
			}

			doc, err := xmldsig.SignDetached(t.Context(), []xmldsig.DetachedReference{{URI: programFirstURI}, {URI: programSecondURI, Transforms: []reference.Transform{tt.program, {Algorithm: c14n.Exclusive}}}}, signer, resolver, xmldsig.DetachedSignOptions{Processing: options})
			if doc != nil || err == nil || calls != 0 || signer.calls != 0 {
				t.Fatalf("doc=%v, error=%v, resolver=%d, signer=%d", doc, err, calls, signer.calls)
			}
		})
	}
}

func TestDetachedDamagedProgramParameters(t *testing.T) {
	program := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: programTrueXPath, Namespaces: map[string]string{"ds": xmldsig.Namespace}}}}

	e, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
	if err != nil {
		t.Fatal(err)
	}

	processing := reference.DefaultOptions()
	processing.Extension = e
	processing.AllowedTransforms = append(processing.AllowedTransforms, reference.XPath)
	key := coreEC(t)

	signed, err := xmldsig.SignDetached(t.Context(), []xmldsig.DetachedReference{{URI: uriUrnData, Transforms: []reference.Transform{program, {Algorithm: c14n.Exclusive}}}}, key, sourceMap(map[string][]byte{uriUrnData: []byte(`<r/>`)}), xmldsig.DetachedSignOptions{Processing: processing})
	if err != nil {
		t.Fatal(err)
	}

	raw := coreXML(t, signed)
	start := strings.Index(raw, "<ds:XPath")

	end := strings.Index(raw, "</ds:XPath>") + len("</ds:XPath>")
	if start < 0 || end < start {
		t.Fatal("parameter missing")
	}

	for _, parameter := range []string{"", raw[start:end] + raw[start:end], `<ds:XPath Filter="intersect">true()</ds:XPath>`, `<ds:XPath><bad/></ds:XPath>`, `<ds:Unknown/>`} {
		t.Run(parameter, func(t *testing.T) {
			changed := coreParse(t, raw[:start]+parameter+raw[end:])
			calls := 0
			resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				calls++
				return nil, errors.New("unexpected resolver call")
			})

			result, err := xmldsig.VerifyDetached(t.Context(), changed, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnData}, Processing: processing})
			if result != nil || err == nil || calls != 0 {
				t.Fatalf("result=%v error=%v calls=%d", result, err, calls)
			}
		})
	}
}

func TestDetachedVerifierPreflightsEveryProgram(t *testing.T) {
	program := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: programTrueXPath, Namespaces: map[string]string{"ds": xmldsig.Namespace}}}}

	allowed, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
	if err != nil {
		t.Fatal(err)
	}

	processing := reference.DefaultOptions()
	processing.Extension = allowed
	processing.AllowedTransforms = append(processing.AllowedTransforms, reference.XPath)
	key := coreEC(t)

	signed, err := xmldsig.SignDetached(t.Context(), []xmldsig.DetachedReference{{URI: programFirstURI}, {URI: programSecondURI, Transforms: []reference.Transform{program, {Algorithm: c14n.Exclusive}}}}, key, sourceMap(map[string][]byte{programFirstURI: []byte("raw"), programSecondURI: []byte(`<r/>`)}), xmldsig.DetachedSignOptions{Processing: processing})
	if err != nil {
		t.Fatal(err)
	}

	program.XPath[0].Expression = "false()"

	denied, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
	if err != nil {
		t.Fatal(err)
	}

	processing.Extension = denied
	calls := 0
	resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		return nil, errors.New("unexpected resolver call")
	})

	result, err := xmldsig.VerifyDetached(t.Context(), signed, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{programFirstURI, programSecondURI}, Processing: processing})
	if result != nil || err == nil || calls != 0 {
		t.Fatalf("result=%v error=%v calls=%d", result, err, calls)
	}
}

func TestDetachedProgramParameters(t *testing.T) {
	for _, program := range []reference.Transform{
		{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: programTrueXPath}}},
		{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "boolean(//p:value)", Namespaces: map[string]string{"p": uriUrnData}}}},
		{Algorithm: reference.XPathFilter2, XPath: []reference.XPathExpression{
			{Expression: "/", Filter: filterIntersect},
			{Expression: "//p:value", Filter: "union", Namespaces: map[string]string{"p": uriUrnData}},
			{Expression: "//absent", Filter: "subtract"},
		}},
		{Algorithm: reference.XSLT, Stylesheet: []byte(`<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:p="urn:data" version="1.0"><xsl:output method="text"/><xsl:template match="/"><xsl:value-of select="//p:value"/></xsl:template></xsl:stylesheet>`)},
	} {
		t.Run(program.Algorithm+string(program.Stylesheet), func(t *testing.T) {
			testDetachedProgramParameters(t, program)
		})
	}
}

func testDetachedProgramParameters(t *testing.T, program reference.Transform) {
	t.Helper()

	program = serializedProgramContext(program)

	e, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
	if err != nil {
		t.Fatal(err)
	}

	processing := reference.DefaultOptions()
	processing.Extension = e
	processing.AllowedTransforms = append(processing.AllowedTransforms, program.Algorithm)

	transforms := []reference.Transform{program}
	if program.Algorithm == reference.XPath && program.XPath[0].Expression == programTrueXPath {
		// The recipe may omit markup bindings; the application has approved
		// the complete context that the serializer places in the XML.
		transforms = []reference.Transform{{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: programTrueXPath}}}}
	}

	if program.Algorithm != reference.XSLT {
		transforms = append(transforms, reference.Transform{Algorithm: c14n.Exclusive, InclusivePrefixes: []string{"p"}})
	}

	key := coreEC(t)
	resolver := sourceMap(map[string][]byte{uriUrnData: []byte(`<r xmlns:p="urn:data"><p:value>123</p:value></r>`)})

	signed, err := xmldsig.SignDetached(t.Context(), []xmldsig.DetachedReference{{URI: uriUrnData, Transforms: transforms}}, key, resolver, xmldsig.DetachedSignOptions{Processing: processing})
	if err != nil {
		t.Fatal(err)
	}

	parsed := coreParse(t, coreXML(t, signed))
	assertDetachedProgramXML(t, parsed, program)

	result, err := xmldsig.VerifyDetached(t.Context(), parsed, key.Public(), resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: []string{uriUrnData}, Processing: processing})
	if err != nil {
		t.Fatal(err)
	}

	if program.Algorithm == reference.XSLT {
		var output bytes.Buffer
		if _, err := result.References()[0].WriteDigestInput(t.Context(), &output); err != nil || output.String() != "123" {
			t.Fatalf("XSLT output %q: %v", output.String(), err)
		}
	}
}

func serializedProgramContext(program reference.Transform) reference.Transform {
	// Approval covers the complete namespace context present in XML,
	// including the prefixes used by the signature/parameter markup.
	for i := range program.XPath {
		if program.XPath[i].Namespaces == nil {
			program.XPath[i].Namespaces = make(map[string]string)
		}

		program.XPath[i].Namespaces["ds"] = xmldsig.Namespace
		if program.Algorithm == reference.XPathFilter2 {
			program.XPath[i].Namespaces["xf"] = reference.XPathFilter2
		}
	}

	if program.Algorithm == reference.XSLT {
		program.Stylesheet = bytes.Replace(program.Stylesheet, []byte(`version="1.0"`), []byte(`xmlns:ds="`+xmldsig.Namespace+`" version="1.0"`), 1)
	}

	return program
}

func assertDetachedProgramXML(t *testing.T, parsed *document.Document, program reference.Transform) {
	t.Helper()
	container := findImportElement(t, parsed.Root(), document.Name{Space: xmldsig.Namespace, Local: "Transforms"})

	parameterNodes := container.Children()[0].Children()
	if program.Algorithm == reference.XSLT {
		if len(parameterNodes) != 1 {
			t.Fatalf("stylesheet missing: %s", coreXML(t, parsed))
		}

		assertImportedTree(t, parameterNodes[0], coreParse(t, string(program.Stylesheet)).Root())
	} else {
		if len(parameterNodes) != len(program.XPath) {
			t.Fatalf("XPath parameters missing: %s", coreXML(t, parsed))
		}

		assertXPathParameters(t, parameterNodes, program.XPath)

		inclusive := container.Children()[1].Children()
		if len(inclusive) != 1 || inclusive[0].Name() != (document.Name{Space: c14n.Exclusive, Local: "InclusiveNamespaces"}) {
			t.Fatal("InclusiveNamespaces missing")
		}

		if prefixes, _ := inclusive[0].Attribute(document.Name{Local: "PrefixList"}); prefixes != "p" {
			t.Fatal(prefixes)
		}
	}
}

func assertXPathParameters(t *testing.T, parameterNodes []document.Element, expected []reference.XPathExpression) {
	t.Helper()

	for i, parameter := range parameterNodes {
		want := expected[i]
		if parameter.Text() != want.Expression {
			t.Fatalf("expression %q != %q", parameter.Text(), want.Expression)
		}

		filter, _ := parameter.Attribute(document.Name{Local: "Filter"})
		if filter != want.Filter {
			t.Fatalf("Filter %q != %q", filter, want.Filter)
		}

		for prefix, uri := range want.Namespaces {
			if got, _ := parameter.Namespace(prefix); got != uri {
				t.Fatalf("namespace %s = %q, want %q", prefix, got, uri)
			}
		}
	}
}

func FuzzVerifyDetached(f *testing.F) {
	seed, err := os.ReadFile(filepath.Join("..", "testdata", "detached", "ec256-cm0.java.xml"))
	if err != nil {
		f.Fatal(err)
	}

	key := loadDetachedKey(f, "ec256.pub.pem")
	uris, resolver := loadDetachedResources(f)
	f.Add(seed)
	f.Add([]byte(`<r/>`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}

		doc, err := document.Parse(t.Context(), data, document.DefaultLimits())
		if err != nil {
			return
		}

		result, err := xmldsig.VerifyDetached(context.Background(), doc, key, resolver, xmldsig.DetachedVerifyOptions{ExpectedURIs: uris})
		if err != nil && result != nil {
			t.Fatal("partial verification result")
		}

		if err == nil && len(result.References()) != len(uris) {
			t.Fatal("incomplete reference set")
		}
	})
}

func loadDetachedResources(t testing.TB) ([]string, xmldsig.Resolver) {
	t.Helper()

	dir := filepath.Join("..", "testdata", "detached")

	data, err := os.ReadFile(filepath.Join(dir, "resources.json"))
	if err != nil {
		t.Fatal(err)
	}

	var entries []struct {
		URI  string `json:"uri"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}

	uris := make([]string, 0, len(entries))

	resources := map[string][]byte{}

	for _, e := range entries {
		contents, err := os.ReadFile(filepath.Join(dir, e.Path))
		if err != nil {
			t.Fatal(err)
		}

		resources[e.URI] = contents
		uris = append(uris, e.URI)
	}

	return uris, sourceMap(resources)
}

func loadDetachedKey(t testing.TB, name string) crypto.PublicKey {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "testdata", "detached", name))
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("bad fixture PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func sourceMap(resources map[string][]byte) xmldsig.Resolver {
	return xmldsig.ResolverFunc(func(ctx context.Context, uri string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		data, ok := resources[uri]
		if !ok {
			return nil, fmt.Errorf("resource not allowed: %s", uri)
		}

		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

func signDetached(t testing.TB, key crypto.Signer, refs []xmldsig.DetachedReference, resolver xmldsig.Resolver, opt xmldsig.DetachedSignOptions) *document.Document {
	t.Helper()

	doc, err := xmldsig.SignDetached(context.Background(), refs, key, resolver, opt)
	if err != nil {
		t.Fatal(err)
	}

	return parse(t, xmlString(t, doc))
}

type observedReader struct {
	io.Reader
	closes   int
	reads    int
	closeErr error
}

func (r *observedReader) Read(p []byte) (int, error) { r.reads++; return r.Reader.Read(p) }

func (r *observedReader) Close() error { r.closes++; return r.closeErr }

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type stuckReader struct{}

func (stuckReader) Read([]byte) (int, error) { return 0, nil }

type badCountReader struct{}

func (badCountReader) Read([]byte) (int, error) { return -1, nil }

func TestCanonicalizedReferenceReadsAndTransformsOnce(t *testing.T) {
	source := `<r xmlns:u="urn:unused">text</r>`
	calls := 0
	resolver := xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		calls++
		value := source
		if calls > 1 {
			value = `<r>changed</r>`
		}
		return io.NopCloser(strings.NewReader(value)), nil
	})
	program := reference.Transform{Algorithm: reference.XPath, XPath: []reference.XPathExpression{{Expression: "true()", Namespaces: map[string]string{"xml": document.XMLNamespace, "ds": xmldsig.Namespace}}}}
	engine, err := transform.NewEngine(transform.Config{AllowedPrograms: []reference.Transform{program}})
	if err != nil {
		t.Fatal(err)
	}
	options := xmldsig.SignatureOptions{External: &xmldsig.ExternalReferences{Resolver: resolver, AllowedURIs: []string{uriUrnXML}}, Processing: reference.DefaultOptions()}
	options.Processing.Extension = engine
	options.Processing.AllowedTransforms = append(options.Processing.AllowedTransforms, reference.XPath)
	draft, selected, err := xmldsig.BuildTemplate(t.Context(), nil, document.Element{}, xmldsig.SignatureTemplate{SignatureMethod: xmldsig.ECDSASHA256, References: []xmldsig.ReferenceTemplate{{URI: uriUrnXML, Transforms: []reference.Transform{program}}}})
	if err != nil {
		t.Fatal(err)
	}
	// Signing and its self-verification each require the same stable resource.
	options.External.Resolver = xmldsig.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(source)), nil
	})
	key := coreEC(t)
	signed, err := xmldsig.SignTemplate(t.Context(), draft, selected, key, xmldsig.TemplateSignOptions{Validation: options})
	if err != nil {
		t.Fatal(err)
	}
	options.External.Resolver = resolver
	calls = 0
	checked, err := xmldsig.VerifySignature(t.Context(), signed, signed.Root(), key.Public(), options)
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	var alternate bytes.Buffer
	_, err = checked.References()[0].WriteCanonicalizedInput(t.Context(), &alternate, reference.Transform{Algorithm: c14n.Exclusive})
	if err != nil || calls != 1 || alternate.String() != `<r>text</r>` {
		t.Fatal(alternate.String(), calls, err)
	}
	alternate.Reset()
	if _, err := checked.References()[0].WriteCanonicalizedInput(t.Context(), &alternate, reference.Transform{Algorithm: c14n.Exclusive}); !errors.Is(err, xmldsig.ErrDigest) {
		t.Fatal("changed resource was accepted", err)
	}
}
