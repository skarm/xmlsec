package xmlenc_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestElementPlaintextProfile(t *testing.T) {
	ctx := context.Background()
	kek := make([]byte, 32)
	rsaKey := key(t)
	// A correctly authenticated octet stream may still be invalid #Element
	// plaintext. Relabeling Type does not corrupt the GCM authentication tag.
	for _, rsaTransport := range []bool{false, true} {
		for _, tc := range []struct {
			name, xml string
			valid     bool
		}{
			{"element", `<r>й é 😀</r>`, true},
			{"empty element", `<r/>`, true},
			{"uncomposable combining mark", "<r>q\u0301</r>", true},
			{"long NFC run", "<\U00010000>q" + strings.Repeat("\u0315", 63) + "</\U00010000>", true},
			{"long non-NFC run", "<r>a" + strings.Repeat("\u0315", 63) + "\u0300</r>", false},
			{"original CGJ", "<r>q" + strings.Repeat("\u0315", 31) + "\u034f\u0300</r>", true},
			{"decomposed text", "<r>e\u0301</r>", false},
			{"decomposed name", "<e\u0301/>", false},
			{"decomposed attribute", "<r a=\"и\u0306\"/>", false},
			{"prolog comment", `<!--before--><r/>`, false},
			{"epilog comment", `<r/><!--after-->`, false},
			{"epilog PI", `<r/><?after data?>`, false},
			{"declaration", `<?xml version="1.0"?><r/>`, false},
			{"leading whitespace", " <r/>", false},
			{"trailing whitespace", "<r/>\n", false},
			{"multiple roots", `<r/><s/>`, false},
		} {
			t.Run(tc.name+"/"+map[bool]string{false: nameWrap, true: "RSA"}[rsaTransport], func(t *testing.T) { testElementPlaintextProfileCase(t, &rsaTransport, &ctx, &tc, &rsaKey, &kek) })
		}
	}
	// UTF-16 is a supported document input encoding, but not XMLENC plaintext
	// for #Element (XML Encryption 1.1 section 4.3).
	units := utf16.Encode([]rune(`<r/>`))
	utf16XML := make([]byte, 2, 2+2*len(units))

	utf16XML[0], utf16XML[1] = 0xff, 0xfe
	for _, u := range units {
		utf16XML = append(utf16XML, byte(u), byte(u>>8))
	}

	encrypted, err := xmlenc.EncryptBytesWithKeyWrap(ctx, utf16XML, kek, xmlenc.KeyWrapOptions{})
	if err != nil {
		t.Fatal(err)
	}

	raw, _ := encrypted.XML(ctx)

	labeled := parse(t, []byte(strings.Replace(string(raw), "<xenc:EncryptedData ", "<xenc:EncryptedData Type=\""+xmlenc.ElementType+"\" ", 1)))
	if result, err := xmlenc.DecryptDocumentWithKeyWrap(ctx, labeled, kek, xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
		t.Fatalf("UTF-16 #Element accepted: %v", err)
	}
}

func testElementPlaintextProfileCase(t *testing.T, rsaTransport *bool, ctx *context.Context, tc *struct {
	name  string
	xml   string
	valid bool
}, rsaKey **rsa.PrivateKey, kek *[]byte,
) {
	var (
		encrypted *document.Document
		err       error
	)
	if *rsaTransport {
		encrypted, err = xmlenc.EncryptBytes(*ctx, []byte(tc.xml), &(*rsaKey).PublicKey, xmlenc.Options{})
	} else {
		encrypted, err = xmlenc.EncryptBytesWithKeyWrap(*ctx, []byte(tc.xml), *kek, xmlenc.KeyWrapOptions{})
	}

	if err != nil {
		t.Fatal(err)
	}

	raw, err := encrypted.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	labeled := parse(t, []byte(strings.Replace(string(raw), "<xenc:EncryptedData ", "<xenc:EncryptedData Type=\""+xmlenc.ElementType+"\" ", 1)))

	var result *document.Document
	if *rsaTransport {
		result, err = xmlenc.DecryptDocument(*ctx, labeled, *rsaKey, xmlenc.Options{})
	} else {
		result, err = xmlenc.DecryptDocumentWithKeyWrap(*ctx, labeled, *kek, xmlenc.KeyWrapOptions{})
	}

	if tc.valid && (err != nil || result == nil) || !tc.valid && (result != nil || !errors.Is(err, xmlenc.ErrDecrypt)) {
		t.Fatalf("valid=%v result=%v error=%v", tc.valid, result != nil, err)
	}

	if tc.valid {
		sameXML(t, parse(t, []byte(tc.xml)), result)
	}
}

func TestEncryptElementRefusesNormalization(t *testing.T) {
	doc := parse(t, []byte("<r>e\u0301</r>"))
	before, _ := doc.XML(t.Context())

	ctx := context.Background()
	if result, err := xmlenc.EncryptDocumentWithKeyWrap(ctx, doc, make([]byte, 32), xmlenc.KeyWrapOptions{}); result != nil || !errors.Is(err, xmlenc.ErrPolicy) {
		t.Fatalf("normalized or encrypted NFD input: %v", err)
	}

	after, _ := doc.XML(ctx)
	if string(after) != string(before) {
		t.Fatal("source changed")
	}
}
