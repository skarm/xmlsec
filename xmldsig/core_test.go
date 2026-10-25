package xmldsig_test

import (
	"bytes"
	"context"
	"crypto"

	// #nosec G406 -- Explicit bounded legacy compatibility only.
	"crypto/dsa" //nolint:staticcheck // XMLDSig 1.1 requires legacy DSA verification; generation is disabled.
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/xmldsig"
)

const ds4 = xmldsig.Namespace

func TestLegacyXMLDSigFixtures(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy compatibility is disabled in FIPS mode")
	}

	for _, test := range []struct {
		name   string
		method string
	}{{"dsa", xmldsig.DSASHA1}, {"rsa", xmldsig.RSASHA1}} {
		t.Run(test.name, func(t *testing.T) { testLegacyXMLDSigFixture(t, test.name, test.method) })
	}
}

func testLegacyXMLDSigFixture(t *testing.T, name, method string) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "testdata", "legacy-dsig", name+"-sha1.xml"))
	if err != nil {
		t.Fatal(err)
	}

	key := coreFixtureKey(t, filepath.Join("..", "legacy-dsig", name+"-public.pem"))
	d := coreParse(t, string(raw))

	selected := xmldsig.Signatures(d)[0]
	if _, err := xmldsig.VerifySignature(t.Context(), d, selected, key, xmldsig.SignatureOptions{}); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal("default accepted legacy", err)
	}

	opt := xmldsig.SignatureOptions{Policy: xmldsig.LegacyVerificationPolicy(), ExpectedURIs: []string{"#root", nameData}, RequiredElements: []document.Element{d.Root(), d.Root().Children()[0]}}

	result, report, err := xmldsig.VerifySignatureDetailed(t.Context(), d, selected, key, opt)
	if err != nil || result == nil || report == nil {
		t.Fatal(result, report, err)
	}

	if len(result.References()) != 2 || result.SignatureMethod() != method || len(result.KeyFingerprintSHA256()) != 64 || !result.CoversElement(d.Root()) {
		t.Fatal("incomplete authenticated result")
	}

	if _, err := xmldsig.Verify(t.Context(), d, key, xmldsig.VerifyOptions{Policy: opt.Policy}); err != nil {
		t.Fatal(err)
	}

	_, err = xmldsig.VerifySignatureWithKeyInfo(t.Context(), d, selected, xmldsig.KeyInfoVerifyOptions{
		Signature: opt, SelectTrustedKey: func(_ context.Context, info *keyinfo.Result) (int, error) {
			candidates := info.Candidates()
			if len(candidates) != 1 || candidates[0].FingerprintSHA256() != result.KeyFingerprintSHA256() {
				return 0, xmldsig.ErrKeyInfoTrust
			}

			return 0, nil
		},
	})
	if err != nil {
		t.Fatal("pinned KeyInfo", err)
	}

	if dsaKey, ok := key.(*dsa.PublicKey); ok {
		testLegacyDSAContextSignature(t, d, dsaKey, result.KeyFingerprintSHA256(), opt)
	}

	changed := coreParse(t, strings.Replace(string(raw), "legacy fixture", "changed fixture", 1))
	if _, err := xmldsig.VerifySignature(t.Context(), changed, xmldsig.Signatures(changed)[0], key, xmldsig.SignatureOptions{Policy: opt.Policy}); !errors.Is(err, xmldsig.ErrDigest) {
		t.Fatal("changed data", err)
	}

	testLegacyMessageEncoding(t, selected, key, method, opt.Policy)
	testLegacyGenerationBlocked(t, key, method, opt.Policy)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := xmldsig.VerifySignature(ctx, d, selected, key, opt); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func testLegacyDSAContextSignature(t *testing.T, doc *document.Document, key *dsa.PublicKey, pin string, validation xmldsig.SignatureOptions) {
	t.Helper()

	xml := coreXML(t, doc)
	for _, field := range []string{"P", "Q", "G"} {
		start := strings.Index(xml, "<ds:"+field+">")

		end := strings.Index(xml, "</ds:"+field+">") + len("</ds:"+field+">")
		if start < 0 || end <= start {
			t.Fatal("missing independent fixture parameter", field)
		}

		xml = xml[:start] + xml[end:]
	}

	abbreviated := coreParse(t, xml)
	selected := xmldsig.Signatures(abbreviated)[0]

	validation.RequiredElements = []document.Element{abbreviated.Root()}

	options := xmldsig.KeyInfoVerifyOptions{Signature: validation, KeyInfo: keyinfo.Options{DSAParameters: &key.Parameters}, SelectTrustedKey: func(_ context.Context, info *keyinfo.Result) (int, error) {
		if len(info.Candidates()) != 1 || info.Candidates()[0].FingerprintSHA256() != pin {
			return -1, xmldsig.ErrKeyInfoTrust
		}

		return 0, nil
	}}
	if result, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), abbreviated, selected, options); err != nil || !result.CoversElement(abbreviated.Root()) {
		t.Fatal("independent signature with application parameter context", err)
	}

	options.KeyInfo.DSAParameters = nil
	if result, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), abbreviated, selected, options); result != nil || !errors.Is(err, keyinfo.ErrUnsupported) {
		t.Fatal("missing parameter context was guessed", err)
	}

	options.KeyInfo.DSAParameters = &key.Parameters

	options.Signature.Policy = xmldsig.DefaultPolicy()
	if result, err := xmldsig.VerifySignatureWithKeyInfo(t.Context(), abbreviated, selected, options); result != nil || !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal("parameter context enabled legacy acceptance", err)
	}
}

func testLegacyMessageEncoding(t *testing.T, selected document.Element, key crypto.PublicKey, method string, policy xmldsig.Policy) {
	t.Helper()

	var message bytes.Buffer
	if err := c14n.WriteElement(t.Context(), &message, selected.Children()[0], c14n.Options{Algorithm: c14n.Exclusive}); err != nil {
		t.Fatal(err)
	}

	sig, err := base64.StdEncoding.DecodeString(selected.Children()[1].Text())
	if err != nil {
		t.Fatal(err)
	}

	if err := xmldsig.VerifyMessage(t.Context(), message.Bytes(), sig, key, method, policy); err != nil {
		t.Fatal("message API", err)
	}

	for _, value := range [][]byte{sig[:len(sig)-1], bytes.Repeat([]byte{0}, len(sig)), append(bytes.Clone(sig), 0)} {
		if err := xmldsig.VerifyMessage(t.Context(), message.Bytes(), value, key, method, policy); !errors.Is(err, xmldsig.ErrSignature) {
			t.Fatal("malformed signature", err)
		}
	}

	if method == xmldsig.DSASHA1 {
		derSig, err := asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{new(big.Int).SetBytes(sig[:20]), new(big.Int).SetBytes(sig[20:])})
		if err != nil {
			t.Fatal(err)
		}

		if err := xmldsig.VerifyMessage(t.Context(), message.Bytes(), derSig, key, method, policy); !errors.Is(err, xmldsig.ErrSignature) {
			t.Fatal("DER instead of r||s", err)
		}
	}

	limited := policy

	limited.MaxCanonicalBytes = message.Len() - 1
	if err := xmldsig.VerifyMessage(t.Context(), message.Bytes(), sig, key, method, limited); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal("message limit", err)
	}
}

func testLegacyGenerationBlocked(t *testing.T, key crypto.PublicKey, method string, policy xmldsig.Policy) {
	t.Helper()

	probe := &legacySigningProbe{key: key}
	if _, err := xmldsig.SignMessage(t.Context(), []byte("message"), probe, method, policy); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal("legacy message generation", err)
	}

	if _, err := xmldsig.SignEnveloped(t.Context(), coreParse(t, `<root ID="root"/>`), probe, xmldsig.SignOptions{Policy: policy, SignatureMethod: method}); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal("legacy XML generation", err)
	}

	template, selected := paramTemplate(t, method, xmldsig.SignatureParameters{})
	if _, err := xmldsig.SignTemplate(t.Context(), template, selected, probe, xmldsig.TemplateSignOptions{Validation: xmldsig.SignatureOptions{Policy: policy}}); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal("legacy template generation", err)
	}

	if probe.calls != 0 {
		t.Fatal("legacy generation reached private signer")
	}
}

func TestLegacyDSAKeyValidation(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("legacy compatibility is disabled in FIPS mode")
	}

	key := coreFixtureKey(t, filepath.Join("..", "legacy-dsig", "dsa-public.pem")).(*dsa.PublicKey)
	for _, mutate := range []func(*dsa.PublicKey){
		func(k *dsa.PublicKey) { k.P = nil }, func(k *dsa.PublicKey) { k.Q = nil },
		func(k *dsa.PublicKey) { k.G = big.NewInt(1) }, func(k *dsa.PublicKey) { k.Y = new(big.Int).Set(k.P) },
		func(k *dsa.PublicKey) { k.P = new(big.Int).Lsh(big.NewInt(1), 16384) },
		func(k *dsa.PublicKey) { k.Q = new(big.Int).Sub(k.Q, big.NewInt(1)) },
		func(k *dsa.PublicKey) { k.Y = new(big.Int).Sub(k.P, big.NewInt(1)) },
	} {
		bad := *key
		mutate(&bad)

		if err := xmldsig.VerifyMessage(t.Context(), nil, make([]byte, 40), &bad, xmldsig.DSASHA1, xmldsig.LegacyVerificationPolicy()); !errors.Is(err, xmldsig.ErrKey) {
			t.Fatal(err)
		}
	}

	if err := xmldsig.VerifyMessage(t.Context(), nil, make([]byte, 40), (*dsa.PublicKey)(nil), xmldsig.DSASHA1, xmldsig.LegacyVerificationPolicy()); !errors.Is(err, xmldsig.ErrKey) {
		t.Fatal(err)
	}
}

func TestLegacyMethodsFIPS(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("run with GODEBUG=fips140=only")
	}

	if err := xmldsig.VerifyMessage(t.Context(), nil, nil, nil, xmldsig.DSASHA1, xmldsig.LegacyVerificationPolicy()); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal(err)
	}

	if _, err := xmldsig.ComputeHMAC(t.Context(), nil, bytes.Repeat([]byte{1}, 80), xmldsig.HMACSHA1, 0, xmldsig.LegacyHMACPolicy()); !errors.Is(err, xmldsig.ErrPolicy) {
		t.Fatal(err)
	}
}

func TestCoreForms(t *testing.T) {
	key := coreEC(t)
	obj := `<ds:Object Id="data" MimeType="text/xml"><p:item xmlns:p="urn:item">original</p:item><!--comment--></ds:Object>`

	cases := []struct {
		name          string
		xml           string
		targetLocal   string
		targetID      string
		expectRoot    bool
		expectCovered bool
		bytes         string
		canonical     bool
	}{
		{"enveloping", coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, c14n.Exclusive), obj), nameObject, nameData2, false, true, "", true},
		{"sibling", `<root><item ID="data">original</item>` + coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, c14n.Exclusive), "") + `<unsigned>mutable</unsigned></root>`, "item", nameData2, false, true, "", true},
		{"nested", `<root><item ID="data">original</item><container>` + coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, c14n.Canonical11), "") + `</container></root>`, "item", nameData2, false, true, "", true},
		{"whole", `<!--before--><root ID="data"><item>original</item>` + coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef("", xmldsig.EnvelopedSignature, c14n.Exclusive), "") + `</root>`, nameRoot, nameData2, true, true, "", true},
		{"root-id", `<root ID="data">` + coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, xmldsig.EnvelopedSignature, c14n.Exclusive), "") + `</root>`, nameRoot, nameData2, true, true, "", true},
		{"xpointer-document", `<!--before--><root ID="data">` + coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef("#xpointer(/)", xmldsig.EnvelopedSignature, c14n.Canonical11WithComments), "") + `</root>`, nameRoot, nameData2, true, true, "", true},
		{"xpointer-id", coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef("#xpointer(id('data'))", c14n.ExclusiveWithComments), obj), nameObject, nameData2, false, true, "", true},
		{"implicit-c14n", coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData), obj), nameObject, nameData2, false, true, "", true},
		{"base64", coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, reference.Base64), `<ds:Object Id="data">aGVsbG8=</ds:Object>`), nameObject, nameData2, false, false, "hello", false},
		{"base64-xml", coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, reference.Base64, c14n.Canonical11), `<ds:Object Id="data">`+base64.StdEncoding.EncodeToString([]byte(`<item/>`))+`</ds:Object>`), nameObject, nameData2, false, false, "<item></item>", true},
		{"reparse", coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, c14n.Exclusive, c14n.Exclusive), obj), nameObject, nameData2, false, false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { testCoreFormsCase(t, &tc, &key) })
	}
}

func testCoreFormsCase(t *testing.T, tc *struct {
	name          string
	xml           string
	targetLocal   string
	targetID      string
	expectRoot    bool
	expectCovered bool
	bytes         string
	canonical     bool
}, key **ecdsa.PrivateKey,
) {
	doc := coreParse(t, tc.xml)
	before := coreXML(t, doc)

	signed := coreSign(t, doc, *key, xmldsig.SignatureOptions{})
	if coreXML(t, doc) != before {
		t.Fatal("input mutated")
	}

	selected := xmldsig.Signatures(signed)[0]

	result, report, err := xmldsig.VerifySignatureDetailed(context.Background(), signed, selected, &(*key).PublicKey, xmldsig.SignatureOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if report.Status != xmldsig.Valid || report.SignatureValue != xmldsig.Valid || len(report.References) != 1 || report.References[0].Status != xmldsig.Valid {
		t.Fatalf("report: %+v", report)
	}

	target := coreFind(signed, tc.targetLocal, tc.targetID)
	if result.CoversElement(target) != tc.expectCovered || result.CoversElement(signed.Root()) != tc.expectRoot {
		t.Fatal("coverage mismatch")
	}

	if result.CoversElement(coreFind(doc, tc.targetLocal, tc.targetID)) {
		t.Fatal("foreign snapshot covered")
	}

	ref := result.References()[0]
	if ref.CoversElement(target) != tc.expectCovered || ref.IsCanonicalXML() != tc.canonical {
		t.Fatal("reference semantics")
	}

	if tc.bytes != "" && string(digestInput(t, ref)) != tc.bytes {
		t.Fatalf("payload %q", digestInput(t, ref))
	}

	data := digestInput(t, ref)
	if len(data) > 0 {
		data[0] ^= 0xff
		if bytes.Equal(data, digestInput(t, ref)) {
			t.Fatal("mutable payload alias")
		}
	}

	if tc.expectCovered {
		_, err = xmldsig.VerifySignature(context.Background(), signed, selected, &(*key).PublicKey, xmldsig.SignatureOptions{RequiredElements: []document.Element{target}})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		r, err := xmldsig.VerifySignature(context.Background(), signed, selected, &(*key).PublicKey, xmldsig.SignatureOptions{RequiredElements: []document.Element{target}})
		if !errors.Is(err, xmldsig.ErrPolicy) || r != nil {
			t.Fatal("unproven coverage accepted", err)
		}
	}
}

func TestCoreAlgorithmsAndCanonicalization(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ec256 := coreEC(t)

	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ec521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		key    crypto.Signer
		method string
	}{{rsaKey, xmldsig.RSASHA256}, {rsaKey, xmldsig.RSASHA384}, {rsaKey, xmldsig.RSASHA512}, {ec256, xmldsig.ECDSASHA256}, {ec384, xmldsig.ECDSASHA384}, {ec521, xmldsig.ECDSASHA512}}

	cms := []string{c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments}
	for i, tc := range cases {
		for j, cm := range cms {
			t.Run(fmt.Sprintf("key%d-cm%d", i, j), func(t *testing.T) {
				d := coreParse(t, `<root xmlns:z="urn:unused" xml:lang="en"><item ID="data">original</item>`+coreTemplate("s", tc.method, cm, coreRef(nameData, cm), "")+`</root>`)
				opt := xmldsig.SignatureOptions{AllowedCanonicalizationMethods: []string{cm}, ExpectedURIs: []string{nameData}}

				signed := coreSign(t, d, tc.key, opt)
				if _, err := xmldsig.VerifySignature(context.Background(), signed, xmldsig.Signatures(signed)[0], tc.key.Public(), opt); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCoreMultisignaturesAndPreservation(t *testing.T) {
	ctx := context.Background()
	key1, key2 := coreEC(t), coreEC(t)
	tmpl := func(id, uri string, transforms ...string) string {
		return coreTemplate(id, xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(uri, transforms...), "")
	}

	t.Run("independent", func(t *testing.T) {
		d := coreParse(t, `<root><item ID="data">payload</item>`+tmpl("s1", nameData, c14n.Exclusive)+tmpl("s2", nameData, c14n.Canonical11)+`</root>`)
		first := coreSign(t, d, key1, xmldsig.SignatureOptions{})
		sigs := xmldsig.Signatures(first)
		target := coreFind(first, "item", nameData2)
		ownOpt := xmldsig.SignatureOptions{RequiredElements: []document.Element{target}, ExpectedURIs: []string{nameData}}

		denied, err := xmldsig.SignTemplate(ctx, first, sigs[1], key2, xmldsig.TemplateSignOptions{Validation: ownOpt})
		if denied != nil || !errors.Is(err, xmldsig.ErrPolicy) {
			t.Fatal("missing preservation accepted", err)
		}

		opt := xmldsig.TemplateSignOptions{Validation: ownOpt, Preserve: []xmldsig.SignatureRequirement{{Signature: sigs[0], PublicKey: &key1.PublicKey, Options: ownOpt}}}

		both, err := xmldsig.SignTemplate(ctx, first, sigs[1], key2, opt)
		if err != nil {
			t.Fatal(err)
		}

		for i, key := range []*ecdsa.PrivateKey{key1, key2} {
			r, err := xmldsig.VerifySignature(ctx, both, xmldsig.Signatures(both)[i], &key.PublicKey, xmldsig.SignatureOptions{})
			if err != nil || !r.CoversElement(coreFind(both, "item", nameData2)) {
				t.Fatal(err)
			}
		}

		if _, err := xmldsig.Verify(ctx, both, &key1.PublicKey, xmldsig.VerifyOptions{}); err == nil {
			t.Fatal("old strict profile relaxed")
		}
		// Wrong key for the chosen signature is not rescued by another signature.
		r, report, err := xmldsig.VerifySignatureDetailed(ctx, both, xmldsig.Signatures(both)[1], &key1.PublicKey, xmldsig.SignatureOptions{})
		if r != nil || err == nil || report.SignatureValue != xmldsig.Invalid {
			t.Fatal("another signature/key trusted")
		}
		// A malformed unrelated SignatureValue is outside selected validation.
		modified := strings.Replace(coreXML(t, both), coreFind(both, "Signature", "s2").Children()[1].Text(), "bad-value", 1)

		broken := coreParse(t, modified)
		if _, err := xmldsig.VerifySignature(ctx, broken, xmldsig.Signatures(broken)[0], &key1.PublicKey, xmldsig.SignatureOptions{}); err != nil {
			t.Fatal(err)
		}

		if _, err := xmldsig.VerifySignature(ctx, broken, xmldsig.Signatures(broken)[1], &key2.PublicKey, xmldsig.SignatureOptions{}); err == nil {
			t.Fatal("malformed selected accepted")
		}
	})
	t.Run("would-invalidate", func(t *testing.T) {
		d := coreParse(t, `<root><item ID="data">payload</item>`+tmpl("s1", "", xmldsig.EnvelopedSignature, c14n.Exclusive)+tmpl("s2", nameData, c14n.Exclusive)+`</root>`)
		first := coreSign(t, d, key1, xmldsig.SignatureOptions{})
		before := coreXML(t, first)
		sigs := xmldsig.Signatures(first)

		r, err := xmldsig.SignTemplate(ctx, first, sigs[1], key2, xmldsig.TemplateSignOptions{Preserve: []xmldsig.SignatureRequirement{{Signature: sigs[0], PublicKey: &key1.PublicKey}}})
		if r != nil || !errors.Is(err, xmldsig.ErrPolicy) || !strings.Contains(err.Error(), "would be invalidated") {
			t.Fatal("prior signature invalidated silently", err)
		}

		if before != coreXML(t, first) {
			t.Fatal("input mutated on failure")
		}
		// Changing the other blank signature also invalidates s1: enveloped
		// excludes s1 only, not every Signature in the document.
		mutated := strings.Replace(before, "<ds:SignatureValue/>", "<ds:SignatureValue>YWJj</ds:SignatureValue>", 1)
		if mutated == before {
			mutated = strings.Replace(before, "<ds:SignatureValue></ds:SignatureValue>", "<ds:SignatureValue>YWJj</ds:SignatureValue>", 1)
		}

		bad := coreParse(t, mutated)

		_, err = xmldsig.VerifySignature(ctx, bad, xmldsig.Signatures(bad)[0], &key1.PublicKey, xmldsig.SignatureOptions{})
		if !errors.Is(err, xmldsig.ErrDigest) {
			t.Fatal("other Signature was also excluded", err)
		}
	})
}

func TestCoreDiagnosticsAndWrapping(t *testing.T) {
	key := coreEC(t)
	ctx := context.Background()
	refs := coreRef("#first", c14n.Exclusive) + coreRef("#second", c14n.Exclusive) + coreRef("#third", c14n.Exclusive)
	raw := `<root><item ID="first">one</item><item ID="second">two</item><item ID="third">three</item>` + coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, refs, "") + `<unsigned>ignored</unsigned></root>`
	d := coreSign(t, coreParse(t, raw), key, xmldsig.SignatureOptions{})
	t.Run("all-references", func(t *testing.T) {
		bad := coreParse(t, strings.Replace(coreXML(t, d), ">two<", ">CHANGED<", 1))
		r, report, err := xmldsig.VerifySignatureDetailed(ctx, bad, xmldsig.Signatures(bad)[0], &key.PublicKey, xmldsig.SignatureOptions{})

		var re *xmldsig.ReferenceError
		if r != nil || !errors.Is(err, xmldsig.ErrDigest) || !errors.As(err, &re) || re.Index != 1 {
			t.Fatal(err)
		}

		if report.SignatureValue != xmldsig.Valid || report.References[0].Status != xmldsig.Valid || report.References[1].Status != xmldsig.Invalid || report.References[2].Status != xmldsig.NotChecked {
			t.Fatalf("%+v", report)
		}
	})
	t.Run("unsigned-root", func(t *testing.T) {
		moved := coreParse(t, strings.Replace(coreXML(t, d), `<item ID="first">one</item>`, `<wrapper><item ID="first">one</item></wrapper>`, 1))

		r, err := xmldsig.VerifySignature(ctx, moved, xmldsig.Signatures(moved)[0], &key.PublicKey, xmldsig.SignatureOptions{})
		if err != nil {
			t.Fatal(err)
		}

		if r.CoversElement(moved.Root()) {
			t.Fatal("wrapper covered")
		}

		_, err = xmldsig.VerifySignature(ctx, moved, xmldsig.Signatures(moved)[0], &key.PublicKey, xmldsig.SignatureOptions{RequiredElements: []document.Element{moved.Root()}})
		if !errors.Is(err, xmldsig.ErrPolicy) {
			t.Fatal("wrapping/application mismatch accepted", err)
		}
	})
	t.Run("preflight-later-reference", func(t *testing.T) {
		bad := coreParse(t, strings.Replace(coreXML(t, d), `URI="#second"`, `URI="https://invalid.example/never-fetched"`, 1))

		r, report, err := xmldsig.VerifySignatureDetailed(ctx, bad, xmldsig.Signatures(bad)[0], &key.PublicKey, xmldsig.SignatureOptions{})
		if r != nil || !errors.Is(err, xmldsig.ErrPolicy) || report.SignatureValue != xmldsig.NotChecked || report.References[1].Status != xmldsig.Disallowed {
			t.Fatal(err, report)
		}
	})
}

func TestCoreRepeatedURIAndExpectedSet(t *testing.T) {
	key := coreEC(t)
	refs := coreRef(nameData, c14n.Exclusive) + coreRef(nameData, c14n.Canonical11)
	d := coreParse(t, coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, refs, `<ds:Object Id="data">payload</ds:Object>`))
	opt := xmldsig.SignatureOptions{ExpectedURIs: []string{nameData, nameData}}

	signed := coreSign(t, d, key, opt)
	for _, uris := range [][]string{{nameData}, {nameData, "#other"}, {}, {nameData, nameData, nameData}} {
		r, e := xmldsig.VerifySignature(context.Background(), signed, xmldsig.Signatures(signed)[0], &key.PublicKey, xmldsig.SignatureOptions{ExpectedURIs: uris})
		if r != nil || !errors.Is(e, xmldsig.ErrPolicy) {
			t.Fatal("URI multiset accepted", e)
		}
	}
}

func TestTemplateObjectNamespaceImport(t *testing.T) {
	for _, source := range []string{
		`<payload plain="v"><value>123</value></payload>`,
		`<payload xmlns="urn:payload"><value/><empty xmlns=""><value/></empty></payload>`,
		`<p:payload xmlns:p="urn:payload" p:a="v"><value/></p:payload>`,
		`<p:payload xmlns:p="urn:payload" xmlns="urn:default"><value/><empty xmlns=""/></p:payload>`,
	} {
		for _, hostXML := range []string{`<host ID="host"><before/></host>`, `<host xmlns="urn:host" xmlns:p="urn:conflict" ID="host"><before/></host>`} {
			t.Run(hostXML+source, func(t *testing.T) {
				host, payload := coreParse(t, hostXML), coreParse(t, source)
				hostBefore, payloadBefore := coreXML(t, host), coreXML(t, payload)

				built, _, err := xmldsig.BuildTemplate(t.Context(), host, host.Root(), xmldsig.SignatureTemplate{
					SignatureMethod: xmldsig.ECDSASHA256,
					References:      []xmldsig.ReferenceTemplate{{URI: "#object"}},
					Objects:         []xmldsig.ObjectTemplate{{ID: "object", XML: payload}},
				})
				if err != nil {
					t.Fatal(err)
				}

				reparsed := coreParse(t, coreXML(t, built))
				object := findImportElement(t, reparsed.Root(), document.Name{Space: xmldsig.Namespace, Local: "Object"})
				assertImportedTree(t, object.Children()[0], payload.Root())
				assertImportedTree(t, reparsed.Root().Children()[0], host.Root().Children()[0])

				if coreXML(t, host) != hostBefore || coreXML(t, payload) != payloadBefore {
					t.Fatal("source snapshot changed")
				}
			})
		}
	}
}

func TestCoreTemplateSafety(t *testing.T) {
	key := coreEC(t)
	ctx := context.Background()

	t.Run("self-dependent", func(t *testing.T) {
		for _, uri := range []string{"", "#s", "#xpointer(/)"} {
			d := coreParse(t, coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(uri, c14n.Exclusive), ""))
			count := &coreCountSigner{Signer: key}

			out, err := xmldsig.SignTemplate(ctx, d, xmldsig.Signatures(d)[0], count, xmldsig.TemplateSignOptions{})
			if out != nil || !errors.Is(err, xmldsig.ErrPolicy) || count.calls != 0 {
				t.Fatal(uri, err, count.calls)
			}
		}
	})
	base := coreParse(t, coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, c14n.Exclusive), `<ds:Object Id="data">payload</ds:Object>`))
	signed := coreSign(t, base, key, xmldsig.SignatureOptions{})
	t.Run("no-overwrite", func(t *testing.T) {
		out, e := xmldsig.SignTemplate(ctx, signed, xmldsig.Signatures(signed)[0], key, xmldsig.TemplateSignOptions{})
		if out != nil || e == nil {
			t.Fatal("signature overwritten")
		}
	})
	t.Run("scoped-id-collision", func(t *testing.T) {
		bad := coreParse(t, `<root><x ID="data"/>`+coreXML(t, base)+`</root>`)

		out, e := xmldsig.SignTemplate(ctx, bad, xmldsig.Signatures(bad)[0], key, xmldsig.TemplateSignOptions{})
		if out != nil || !errors.Is(e, reference.ErrInput) {
			t.Fatal("ambiguous ID accepted", e)
		}
	})
	t.Run("untyped-id-is-not-guessed", func(t *testing.T) {
		bad := coreParse(t, `<root><x Id="data"/>`+coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, c14n.Exclusive), "")+`</root>`)

		out, e := xmldsig.SignTemplate(ctx, bad, xmldsig.Signatures(bad)[0], key, xmldsig.TemplateSignOptions{})
		if out != nil || !errors.Is(e, reference.ErrInput) {
			t.Fatal("untyped Id accepted", e)
		}
	})
	t.Run("keyinfo-not-trust", func(t *testing.T) {
		raw := strings.Replace(coreXML(t, base), `<ds:Object`, `<ds:KeyInfo><ds:KeyName>attacker</ds:KeyName><ds:X509Data><ds:X509Certificate>not-a-certificate</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object`, 1)

		d := coreSign(t, coreParse(t, raw), key, xmldsig.SignatureOptions{})
		if _, e := xmldsig.VerifySignature(ctx, d, xmldsig.Signatures(d)[0], &key.PublicKey, xmldsig.SignatureOptions{}); e != nil {
			t.Fatal(e)
		}

		wrong := coreEC(t)
		if _, e := xmldsig.VerifySignature(ctx, d, xmldsig.Signatures(d)[0], &wrong.PublicKey, xmldsig.SignatureOptions{}); e == nil {
			t.Fatal("KeyInfo supplied trust")
		}
	})
	t.Run("concurrent-immutable", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, e := xmldsig.VerifySignature(ctx, signed, xmldsig.Signatures(signed)[0], &key.PublicKey, xmldsig.SignatureOptions{}); e != nil {
					t.Error(e)
				}
			})
		}

		wg.Wait()
	})
}

func TestCoreInvalidOptions(t *testing.T) {
	key := coreEC(t)
	ctx := context.Background()
	base := coreParse(t, coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(nameData, c14n.Exclusive), `<ds:Object Id="data">payload</ds:Object>`))
	d := coreSign(t, base, key, xmldsig.SignatureOptions{})
	sig := xmldsig.Signatures(d)[0]

	for _, tc := range []struct {
		name string
		opt  xmldsig.SignatureOptions
	}{
		{"canonicalization", xmldsig.SignatureOptions{AllowedCanonicalizationMethods: []string{c14n.Canonical11}}},
		{"unknown-c14n", xmldsig.SignatureOptions{AllowedCanonicalizationMethods: []string{"unknown"}}},
		{"byte-limit", xmldsig.SignatureOptions{Policy: xmldsig.Policy{MaxCanonicalBytes: 1}}},
		{"node-limit", xmldsig.SignatureOptions{Processing: reference.Options{MaxNodeVisits: 1}}},
		{"bad-id", xmldsig.SignatureOptions{IDAttribute: document.Name{Local: "not an ID"}}},
		{"foreign-required", xmldsig.SignatureOptions{RequiredElements: []document.Element{base.Root()}}},
		{"max-signatures", xmldsig.SignatureOptions{MaxSignatures: -1}},
		{"transform-denied", xmldsig.SignatureOptions{Processing: reference.Options{AllowedTransforms: []string{reference.Base64}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, e := xmldsig.VerifySignatureDetailed(ctx, d, sig, &key.PublicKey, tc.opt)
			if e == nil || r != nil {
				t.Fatal("invalid options accepted")
			}
		})
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	for _, tc := range []struct {
		name string
		ctx  context.Context
		doc  *document.Document
		sig  document.Element
		key  crypto.PublicKey
	}{
		{"nil-context", nil, d, sig, &key.PublicKey}, {"cancelled", cancelled, d, sig, &key.PublicKey}, {"nil-document", ctx, nil, sig, &key.PublicKey}, {"zero-selection", ctx, d, document.Element{}, &key.PublicKey}, {"foreign-selection", ctx, d, base.Root(), &key.PublicKey}, {"nil-key", ctx, d, sig, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, e := xmldsig.VerifySignatureDetailed(tc.ctx, tc.doc, tc.sig, tc.key, xmldsig.SignatureOptions{})
			if e == nil || r != nil {
				t.Fatal("invalid input accepted")
			}
		})
	}

	var result *xmldsig.SignatureResult
	if result.Signature().Valid() || result.CoversElement(d.Root()) || result.SignatureMethod() != "" || result.KeyFingerprintSHA256() != "" || len(result.References()) != 0 {
		t.Fatal("nil result methods")
	}

	if len(xmldsig.Signatures(nil)) != 0 {
		t.Fatal("nil enumeration")
	}
}

func TestCoreCommentAndManifestSemantics(t *testing.T) {
	key := coreEC(t)
	ctx := context.Background()

	for _, uri := range []string{nameData, "#xpointer(id('data'))"} {
		t.Run(uri, func(t *testing.T) {
			raw := coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, coreRef(uri, c14n.ExclusiveWithComments), `<ds:Object Id="data">text<!--original--></ds:Object>`)
			signed := coreSign(t, coreParse(t, raw), key, xmldsig.SignatureOptions{})
			bad := coreParse(t, strings.Replace(coreXML(t, signed), "<!--original-->", "<!--changed-->", 1))

			r, e := xmldsig.VerifySignature(ctx, bad, xmldsig.Signatures(bad)[0], &key.PublicKey, xmldsig.SignatureOptions{})
			if uri == nameData {
				if e != nil {
					t.Fatal(e)
				}
			} else if r != nil || !errors.Is(e, xmldsig.ErrDigest) {
				t.Fatal("comment not authenticated", e)
			}
		})
	}

	t.Run("manifest-is-opaque", func(t *testing.T) {
		// The direct reference authenticates the Manifest XML, not its targets.
		manifest := `<ds:Object><ds:Manifest Id="manifest"><ds:Reference URI="https://invalid.example/not-fetched"><ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `"/><ds:DigestValue>` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object>`
		refs := strings.Replace(coreRef("#manifest", c14n.Exclusive), `URI="#manifest"`, `URI="#manifest" Type="`+ds4+`Manifest"`, 1)
		d := coreSign(t, coreParse(t, coreTemplate("s", xmldsig.ECDSASHA256, c14n.Exclusive, refs, manifest)), key, xmldsig.SignatureOptions{})

		r, e := xmldsig.VerifySignature(ctx, d, xmldsig.Signatures(d)[0], &key.PublicKey, xmldsig.SignatureOptions{})
		if e != nil {
			t.Fatal(e)
		}

		if len(r.References()) != 1 || r.References()[0].Type() != ds4+"Manifest" {
			t.Fatal("manifest recursion silently claimed")
		}
	})
}

func TestSignaturesInvalidDocuments(t *testing.T) {
	for _, doc := range []*document.Document{nil, new(document.Document)} {
		if got := xmldsig.Signatures(doc); len(got) != 0 {
			t.Fatalf("invalid document returned %d signatures", len(got))
		}
	}
}

func FuzzVerifySignature(f *testing.F) {
	seed, err := os.ReadFile(filepath.Join("..", "testdata", "core", "ec256-enveloping-cm0.jdk.xml"))
	if err != nil {
		f.Fatal(err)
	}

	key := coreFixtureKey(f, "ec256.pub.pem")
	f.Add(seed)
	f.Add([]byte(`<root/>`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			t.Skip()
		}

		d, err := document.Parse(t.Context(), raw, document.DefaultLimits())
		if err != nil {
			return
		}

		signatures := xmldsig.Signatures(d)
		if len(signatures) == 0 {
			return
		}

		result, report, err := xmldsig.VerifySignatureDetailed(context.Background(), d, signatures[0], key, xmldsig.SignatureOptions{Processing: reference.Options{MaxNodeVisits: 100_000}})
		if err != nil {
			if result != nil || report.Status == xmldsig.Valid {
				t.Fatal("partial success")
			}

			return
		}

		if result == nil || report.SignatureValue != xmldsig.Valid || len(result.References()) == 0 {
			t.Fatal("incomplete success")
		}

		for _, r := range report.References {
			if r.Status != xmldsig.Valid {
				t.Fatal("unchecked successful reference")
			}
		}
	})
}

func coreFixtureKey(t testing.TB, name string) crypto.PublicKey {
	t.Helper()

	raw, e := os.ReadFile(filepath.Join("..", "testdata", "core", name))
	if e != nil {
		t.Fatal(e)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("fixture PEM")
	}

	key, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}

	return key
}

func FuzzSignTemplate(f *testing.F) {
	key := coreEC(f)
	f.Add([]byte(coreTemplate("s", xmldsig.ECDSASHA256, "http://www.w3.org/2001/10/xml-exc-c14n#", coreRef(nameData, "http://www.w3.org/2001/10/xml-exc-c14n#"), `<ds:Object Id="data">payload</ds:Object>`)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16<<10 {
			t.Skip()
		}

		d, err := document.Parse(t.Context(), raw, document.DefaultLimits())
		if err != nil {
			return
		}

		signatures := xmldsig.Signatures(d)
		if len(signatures) == 0 {
			return
		}

		before := coreXML(t, d)
		opt := xmldsig.SignatureOptions{Processing: reference.Options{MaxNodeVisits: 100_000}}

		out, err := xmldsig.SignTemplate(context.Background(), d, signatures[0], key, xmldsig.TemplateSignOptions{Validation: opt})
		if coreXML(t, d) != before {
			t.Fatal("input changed")
		}

		if err != nil {
			if out != nil {
				t.Fatal("partial signed output")
			}

			return
		}

		if out == nil {
			t.Fatal("nil success")
		}

		if _, err := xmldsig.VerifySignature(context.Background(), out, xmldsig.Signatures(out)[0], &key.PublicKey, opt); err != nil {
			t.Fatal("invalid signed output", err)
		}
	})
}

func coreParse(t testing.TB, s string) *document.Document {
	t.Helper()

	d, e := document.Parse(t.Context(), []byte(s), document.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}

	return d
}

func coreEC(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}

	return k
}

func coreXML(t testing.TB, d *document.Document) string {
	t.Helper()

	b, e := d.XML(t.Context())
	if e != nil {
		t.Fatal(e)
	}

	return string(b)
}

func coreFind(d *document.Document, local, id string) document.Element {
	var walk func(document.Element) document.Element

	walk = func(e document.Element) document.Element {
		if e.Name().Local == local {
			for _, a := range e.Attributes() {
				if a.Value == id {
					return e
				}
			}
		}

		for _, child := range e.Children() {
			if found := walk(child); found.Valid() {
				return found
			}
		}

		return document.Element{}
	}

	return walk(d.Root())
}

func coreRef(uri string, algorithms ...string) string {
	esc := strings.NewReplacer("&", "&amp;", "\"", "&quot;", "<", "&lt;").Replace(uri)

	tr := ""
	if len(algorithms) > 0 {
		tr = "<ds:Transforms>"

		var trSb83 strings.Builder
		for _, a := range algorithms {
			trSb83.WriteString(`<ds:Transform Algorithm="` + a + `"/>`)
		}

		tr += trSb83.String()
		tr += "</ds:Transforms>"
	}

	return `<ds:Reference URI="` + esc + `">` + tr + `<ds:DigestMethod Algorithm="` + xmldsig.SHA256 + `"/><ds:DigestValue/></ds:Reference>`
}

func coreTemplate(id, method, cm, refs, objects string) string {
	return `<ds:Signature xmlns:ds="` + ds4 + `" Id="` + id + `"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="` + cm + `"/><ds:SignatureMethod Algorithm="` + method + `"/>` + refs + `</ds:SignedInfo><ds:SignatureValue/>` + objects + `</ds:Signature>`
}

func coreSign(t testing.TB, d *document.Document, key crypto.Signer, opt xmldsig.SignatureOptions) *document.Document {
	t.Helper()

	out, e := xmldsig.SignTemplate(context.Background(), d, xmldsig.Signatures(d)[0], key, xmldsig.TemplateSignOptions{Validation: opt})
	if e != nil {
		t.Fatal(e)
	}

	return out
}
