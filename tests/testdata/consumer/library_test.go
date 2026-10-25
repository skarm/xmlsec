package consumer_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/keys"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/resource"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
	"github.com/skarm/xmlsec/xmlenc"
)

func TestLibraryComposition(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Consumer root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Consumer signer"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	certificate, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keys.ParsePrivate(private, keys.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := pki.NewVerifier(pki.Config{Roots: [][]byte{rootDER}})
	if err != nil {
		t.Fatal(err)
	}
	if result, _, err := trust.Verify(ctx, certificate, now, pki.Evidence{}); err != nil || result == nil {
		t.Fatal(err)
	}
	doc, err := document.Parse(ctx, []byte(`<invoice ID="invoice"><amount>42</amount></invoice>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := xmldsig.SignEnveloped(ctx, doc, signer, xmldsig.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := xmldsig.Verify(ctx, signed, signer.Public(), xmldsig.VerifyOptions{ExpectedRoot: document.Name{Local: "invoice"}})
	if err != nil || !verified.Root().Valid() {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{7}, 32)
	encrypted, err := xmlenc.EncryptDocumentWithKey(ctx, signed, secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := xmlenc.DecryptDocumentWithKey(ctx, encrypted, secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xmldsig.Verify(ctx, decrypted, signer.Public(), xmldsig.VerifyOptions{ExpectedRoot: document.Name{Local: "invoice"}}); err != nil {
		t.Fatal(err)
	}
	info, err := keyinfo.Build(ctx, keyinfo.Template{Names: []string{"consumer"}, Certificates: [][]byte{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	described, err := keyinfo.Parse(ctx, info, info.Root(), keyinfo.Options{})
	if err != nil || len(described.KeyNames()) != 1 {
		t.Fatal(err)
	}
	container, err := cms.Sign(ctx, []byte("content"), []cms.Signer{{Key: signer, CertificateDER: certificate}}, cms.SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cms.Parse(ctx, container, cms.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	content, err := parsed.Verify(ctx, [][]byte{certificate}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true})
	if err != nil || string(content.Content()) != "content" {
		t.Fatal(err)
	}
	xmlSigned, _, err := xades.SignBasicEnveloped(ctx, doc, signer, certificate, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xades.VerifyBasicEnveloped(ctx, xmlSigned, xmldsig.Signatures(xmlSigned)[0], certificate, xades.VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	request, err := timestamp.CreateRequest(t.Context(), container, timestamp.RequestOptions{Policy: asn1.ObjectIdentifier{1, 2, 3, 4}})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := timestamp.ParseRequest(request.DER()); err != nil || parsed == nil {
		t.Fatal(err)
	}
}

func TestKeyMaterialLimits(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	limits := keys.Limits{MaxInputBytes: len(encoded), MaxKeyBytes: len(raw)}
	if _, err := keys.ParsePrivate(encoded, limits); err != nil {
		t.Fatal(err)
	}
	limits.MaxKeyBytes--
	if signer, err := keys.ParsePrivate(encoded, limits); signer != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatalf("decoded key limit: %v", err)
	}
	password := []byte("consumer password")
	encryption := keys.EncryptionOptions{Iterations: 1000}
	limits = keys.Limits{MaxKDFWork: 1000}
	encrypted, err := keys.MarshalEncryptedPrivate(t.Context(), key, password, encryption, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.ParseEncryptedPrivate(t.Context(), encrypted, password, limits); err != nil {
		t.Fatal(err)
	}
	limits.MaxKDFWork--
	if signer, err := keys.ParseEncryptedPrivate(t.Context(), encrypted, password, limits); signer != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatalf("KDF limit: %v", err)
	}
}

func TestAttributeDERValidation(t *testing.T) {
	key, certificate := nativeIOSigner(t)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(private, &outer); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	encode := func(class, tag int, compound bool, content []byte) []byte {
		t.Helper()
		raw, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: content})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	oid := asn1.ObjectIdentifier{1, 2, 3, 4}
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		{12, 1, 255},
		{19, 1, '@'},
		{22, 1, 255},
		{30, 2, 0xd8, 0},
		encode(0, asn1.TagGeneralizedTime, false, []byte("20261019010203.10Z")),
	} {
		attribute := encode(0, asn1.TagSequence, true, append(bytes.Clone(oidDER), encode(0, asn1.TagSet, true, value)...))
		input := encode(0, asn1.TagSequence, true, append(bytes.Clone(outer.Bytes), encode(2, 0, true, attribute)...))
		if signer, err := keys.ParsePrivate(input, keys.Limits{}); signer != nil || !errors.Is(err, keys.ErrFormat) {
			t.Fatalf("malformed PKCS#8 attribute %x: %v", value, err)
		}
		signer := cms.Signer{Key: key, CertificateDER: certificate, Attributes: []cms.Attribute{{OID: oid, ValuesDER: [][]byte{value}}}}
		if raw, err := cms.Sign(t.Context(), nil, []cms.Signer{signer}, cms.SignOptions{}); raw != nil || !errors.Is(err, cms.ErrPolicy) {
			t.Fatalf("malformed CMS attribute %x: %v", value, err)
		}
	}
}

func TestPKCS12Limits(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: at, NotAfter: at.Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := keys.ParseCertificate(raw, keys.Limits{MaxCertificateBytes: len(raw)})
	if err != nil {
		t.Fatal(err)
	}
	identity := keys.PKCS12Identity{PrivateKey: key, Certificate: certificate}
	options := keys.PKCS12Options{Encryption: keys.EncryptionOptions{Iterations: 1000}}
	limits := keys.Limits{MaxCertificates: 1, MaxBags: 2, MaxContentInfos: 2, MaxKDFWork: 3000}
	password := []byte("consumer container")
	container, err := keys.MarshalPKCS12(t.Context(), identity, password, options, limits)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := keys.ParsePKCS12(t.Context(), container, password, limits)
	if err != nil || !bytes.Equal(parsed.Certificate.Raw, raw) {
		t.Fatalf("container round trip: %v", err)
	}
	limits.MaxBags = 1
	if result, err := keys.ParsePKCS12(t.Context(), container, password, limits); result != nil || !errors.Is(err, keys.ErrLimit) {
		t.Fatalf("container bag budget: %v", err)
	}
}

func TestNativeCryptoReadersBoundMessageStorage(t *testing.T) {
	key, certificate := nativeIOSigner(t)
	block := bytes.Repeat([]byte("data"), 1024)
	secret := bytes.Repeat([]byte{7}, 32)
	for _, size := range []int{16 << 10, 8 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			source := func() io.Reader { return &repeatedInput{remaining: size, block: block} }
			options := cms.SignOptions{Detached: true, Limits: cms.Limits{MaxBytes: 64 << 10, MaxContentBytes: 16 << 20}}
			var container bytes.Buffer
			allocated := allocatedDuring(t, func() error {
				container.Reset()
				_, err := cms.SignReader(t.Context(), &container, source(), []cms.Signer{{Key: key, CertificateDER: certificate}}, options)
				return err
			})
			if allocated > 512<<10 {
				t.Fatalf("CMS detached signing allocated %d bytes for %d input bytes", allocated, size)
			}
			parsed, err := cms.ParseReader(t.Context(), bytes.NewReader(container.Bytes()), options.Limits)
			if err != nil {
				t.Fatal(err)
			}
			allocated = allocatedDuring(t, func() error {
				result, err := parsed.VerifyReader(t.Context(), source(), [][]byte{certificate}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true})
				if err != nil {
					return err
				}
				if result.Content() != nil || result.ContentSize() != int64(size) {
					return errors.New("detached reader retained message or lost size")
				}
				return nil
			})
			if allocated > 256<<10 {
				t.Fatalf("CMS verification allocated %d bytes", allocated)
			}
			operations := []struct {
				name string
				run  func() error
			}{
				{"timestamp", func() error {
					_, err := timestamp.CreateRequestReader(t.Context(), source(), timestamp.RequestOptions{})
					return err
				}},
				{"XMLDSig", func() error {
					value, err := xmldsig.SignMessageReader(t.Context(), source(), key, xmldsig.ECDSASHA256, xmldsig.Policy{})
					if err != nil {
						return err
					}
					return xmldsig.VerifyMessageReader(t.Context(), source(), value, key.Public(), xmldsig.ECDSASHA256, xmldsig.Policy{})
				}},
				{"HMAC", func() error {
					tag, err := xmldsig.ComputeHMACReader(t.Context(), source(), secret, xmldsig.HMACSHA256, 0, xmldsig.HMACPolicy())
					if err != nil {
						return err
					}
					return xmldsig.VerifyHMACReader(t.Context(), source(), tag, secret, xmldsig.HMACSHA256, 0, xmldsig.HMACPolicy())
				}},
			}
			for _, operation := range operations {
				if allocated := allocatedDuring(t, operation.run); allocated > 256<<10 {
					t.Fatalf("%s allocated %d bytes", operation.name, allocated)
				}
			}
		})
	}
}

func TestNativeReadersPreserveErrorsAndOwnership(t *testing.T) {
	key, certificate := nativeIOSigner(t)
	failure := errors.New("source failed")
	for _, operation := range []func(io.Reader) error{
		func(src io.Reader) error {
			_, err := timestamp.ImprintReader(t.Context(), src, crypto.SHA256)
			return err
		},
		func(src io.Reader) error {
			_, err := cms.SignReader(t.Context(), io.Discard, src, []cms.Signer{{Key: key, CertificateDER: certificate}}, cms.SignOptions{Detached: true})
			return err
		},
		func(src io.Reader) error {
			_, err := xmldsig.SignMessageReader(t.Context(), src, key, xmldsig.ECDSASHA256, xmldsig.Policy{})
			return err
		},
	} {
		closed := false
		src := &trackedInput{Reader: io.MultiReader(strings.NewReader("prefix"), readFunc(func([]byte) (int, error) { return 0, failure })), close: func() error { closed = true; return nil }}
		if err := operation(src); !errors.Is(err, failure) || closed {
			t.Fatalf("read error/ownership: %v closed=%v", err, closed)
		}
	}
	var output bytes.Buffer
	input := &streamingInput{source: strings.NewReader("too long")}
	if n, err := cms.SignReader(t.Context(), &output, input, []cms.Signer{{Key: key, CertificateDER: certificate}}, cms.SignOptions{Detached: true, Limits: cms.Limits{MaxContentBytes: 3}}); n != 0 || output.Len() != 0 || !errors.Is(err, cms.ErrPolicy) || input.bytes > 4 {
		t.Fatal("content budget", n, err, input.bytes)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := timestamp.ImprintReader(ctx, strings.NewReader("data"), crypto.SHA256); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestXMLDecryptionAvoidsEncodedTextAndPlaintextCopies(t *testing.T) {
	const size = 1 << 20
	plaintext := bytes.Repeat([]byte("x"), size)
	secret := bytes.Repeat([]byte{3}, 32)
	encrypted, err := xmlenc.EncryptBytesWithKey(t.Context(), plaintext, secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	allocated := allocatedDuring(t, func() error {
		decoded, err := xmlenc.DecryptBytesWithKey(t.Context(), encrypted, secret, xmlenc.SymmetricOptions{})
		if err != nil {
			return err
		}
		if !bytes.Equal(decoded, plaintext) {
			return errors.New("decrypted bytes changed")
		}
		return nil
	})
	if allocated > size+256<<10 {
		t.Fatalf("decryption allocated %d bytes for %d owned plaintext bytes", allocated, size)
	}
}

func TestKeyInfoExternalXMLDoesNotRetainSourceBytes(t *testing.T) {
	const namespace = "http://www.w3.org/2000/09/xmldsig#"
	remote := `<ds:KeyInfo xmlns:ds="` + namespace + `"><!--` + strings.Repeat("x", 1<<20) + `--><ds:KeyName>stream</ds:KeyName></ds:KeyInfo>`
	local, err := document.Parse(t.Context(), []byte(`<ds:KeyInfo xmlns:ds="`+namespace+`" xmlns:k="http://www.w3.org/2009/xmldsig11#"><k:KeyInfoReference URI="urn:stream:key"/><k:KeyInfoReference URI="urn:stream:key"/></ds:KeyInfo>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	baseline := allocatedDuring(t, func() error {
		doc, err := document.ParseReader(t.Context(), strings.NewReader(remote), document.DefaultLimits())
		if err != nil {
			return err
		}
		_, err = keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
		return err
	})
	allocated := allocatedDuring(t, func() error {
		opened, closed := 0, 0
		resolver := resource.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
			opened++
			return &trackedInput{Reader: strings.NewReader(remote), close: func() error { closed++; return nil }}, nil
		})
		result, err := keyinfo.Parse(t.Context(), local, local.Root(), keyinfo.Options{External: &keyinfo.ExternalResources{Resolver: resolver, AllowedURIs: []string{"urn:stream:key"}}})
		if err != nil {
			return err
		}
		if opened != 1 || closed != 1 || len(result.KeyNames()) != 2 {
			return errors.New("external XML cache/ownership changed")
		}
		return nil
	})
	if allocated > baseline+256<<10 {
		t.Fatalf("KeyInfo resource allocated %d bytes versus parsed-model baseline %d", allocated, baseline)
	}
}

func TestCMSAttachedWorkingStorage(t *testing.T) {
	key, certificate := nativeIOSigner(t)
	signers := []cms.Signer{{Key: key, CertificateDER: certificate}}
	for _, size := range []int{16 << 10, 8 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			message := bytes.Repeat([]byte("x"), size)
			raw, err := cms.Sign(t.Context(), message, signers, cms.SignOptions{})
			if err != nil {
				t.Fatal(err)
			}
			allocated := allocatedDuring(t, func() error {
				n, err := cms.SignReader(t.Context(), io.Discard, bytes.NewBuffer(message), signers, cms.SignOptions{})
				if err == nil && (n < int64(size) || n > int64(size+64<<10)) {
					return errors.New("CMS writer lost encoded bytes")
				}
				return err
			})
			t.Logf("attached signing: %d input bytes, %d allocated bytes", size, allocated)
			if allocated > 256<<10 {
				t.Fatalf("CMS copied resident content: %d allocated", allocated)
			}
			// A general attached reader needs one growing content buffer; signing
			// must not add another copy beyond that collection baseline.
			collection := allocatedDuring(t, func() error {
				var buffer bytes.Buffer
				_, err := io.CopyBuffer(struct{ io.Writer }{&buffer}, &repeatedInput{remaining: size, block: message[:4096]}, make([]byte, 32<<10))
				return err
			})
			allocated = allocatedDuring(t, func() error {
				_, err := cms.SignReader(t.Context(), io.Discard, &repeatedInput{remaining: size, block: message[:4096]}, signers, cms.SignOptions{})
				return err
			})
			if allocated > collection+(256<<10) {
				t.Fatalf("attached reader retained excess content copies: %d allocated, %d collection baseline", allocated, collection)
			}

			parsed, err := cms.ParseReader(t.Context(), bytes.NewReader(raw), cms.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Size() != len(raw) {
				t.Fatal("incorrect CMS size")
			}
			allocated = allocatedDuring(t, func() error {
				result, err := parsed.VerifyReader(t.Context(), nil, [][]byte{certificate}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), RequireCertificateBinding: true, DiscardContent: true})
				if err == nil && (result.Content() != nil || result.ContentSize() != int64(size)) {
					return errors.New("CMS retained discarded content")
				}
				return err
			})
			t.Logf("attached verification without content: %d allocated bytes", allocated)
			if allocated > 256<<10 {
				t.Fatalf("CMS verification copied discarded content: %d allocated", allocated)
			}
			allocated = allocatedDuring(t, func() error {
				n, err := parsed.WriterTo(t.Context()).WriteTo(io.Discard)
				if err == nil && n != int64(len(raw)) {
					return errors.New("CMS DER replay changed length")
				}
				return err
			})
			if allocated > 64<<10 {
				t.Fatalf("CMS DER replay copied container: %d allocated", allocated)
			}

			failure := errors.New("stop DER")
			if n, err := parsed.WriterTo(t.Context()).WriteTo(&prefixFailure{remaining: 128, failure: failure}); n != 128 || !errors.Is(err, failure) {
				t.Fatal("CMS partial output", n, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			sink := &streamingSink{afterWrite: cancel}
			if n, err := parsed.WriterTo(ctx).WriteTo(sink); !errors.Is(err, context.Canceled) || n > 32<<10 {
				t.Fatal("CMS output cancellation", n, err)
			}
			cancel()
			ctx, cancel = context.WithCancel(t.Context())
			reader := bytes.NewReader(message)
			canceledInput := &streamingInput{source: readFunc(func(p []byte) (int, error) { n, err := reader.Read(p); cancel(); return n, err })}
			if n, err := cms.SignReader(ctx, io.Discard, canceledInput, signers, cms.SignOptions{}); n != 0 || !errors.Is(err, context.Canceled) || canceledInput.bytes > 32<<10 {
				t.Fatal("attached read cancellation", n, err, canceledInput.bytes)
			}
			cancel()

			var encoded bytes.Buffer
			input := &streamingInput{source: strings.NewReader(strings.Repeat("x", 1024))}
			if n, err := cms.SignReader(t.Context(), &encoded, input, signers, cms.SignOptions{Limits: cms.Limits{MaxContentBytes: 3}}); n != 0 || encoded.Len() != 0 || !errors.Is(err, cms.ErrPolicy) || input.bytes != 4 {
				t.Fatal("attached input budget", n, err, input.bytes)
			}
		})
	}
}

func TestCMSDiscardedContentIsCollectible(t *testing.T) {
	key, certificate := nativeIOSigner(t)
	retained := retainedHeapDuring(t, func() any {
		results := make([]*cms.Result, 8)
		for i := range results {
			var wire bytes.Buffer
			_, err := cms.SignReader(t.Context(), &wire, &repeatedInput{remaining: 2 << 20, block: []byte("x")}, []cms.Signer{{Key: key, CertificateDER: certificate, Hash: crypto.SHA256}}, cms.SignOptions{})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := cms.ParseReader(t.Context(), &wire, cms.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			results[i], err = parsed.VerifyReader(t.Context(), nil, [][]byte{certificate}, cms.VerifyOptions{ExpectedContentType: cms.DataOID(), DiscardContent: true})
			if err != nil {
				t.Fatal(err)
			}
			if results[i].Content() != nil || results[i].ContentSize() != 2<<20 || len(results[i].Signers()) != 1 {
				t.Fatal("discarded result changed")
			}
		}
		return results
	})
	t.Logf("eight CMS verification results: %d retained heap bytes", retained)
	if retained > 4<<20 {
		t.Fatalf("verification results retained discarded content: %d bytes", retained)
	}
}

func TestCMSAndTimestampCertificateBagWorkingStorage(t *testing.T) {
	key, certificate := nativeIOSigner(t)
	template, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	padding, err := asn1.Marshal(bytes.Repeat([]byte{7}, 256<<10))
	if err != nil {
		t.Fatal(err)
	}
	var certificates [][]byte
	total := 0
	for i := range 4 {
		leaf := *template
		leaf.SerialNumber = big.NewInt(int64(i + 10))
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: padding}}
		raw, err := x509.CreateCertificate(rand.Reader, &leaf, &leaf, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, raw)
		total += len(raw)
	}
	allocated := allocatedDuring(t, func() error {
		_, err := cms.SignReader(t.Context(), io.Discard, strings.NewReader("payload"), []cms.Signer{{Key: key, CertificateDER: certificate}}, cms.SignOptions{ExtraCertificates: certificates})
		return err
	})
	t.Logf("%d certificate bytes: %d allocated bytes", total, allocated)
	if allocated > uint64(total)+(256<<10) {
		t.Fatalf("CMS buffered complete certificate bags: %d allocated", allocated)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "timestamp root"}, NotBefore: template.NotBefore, NotAfter: template.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	tsa := &x509.Certificate{SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "timestamp TSA"}, NotBefore: template.NotBefore, NotAfter: template.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}
	tsaDER, err := x509.CreateCertificate(rand.Reader, tsa, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	policy := asn1.ObjectIdentifier{1, 2, 3, 4, 1}
	query, err := timestamp.CreateRequest(t.Context(), []byte("payload"), timestamp.RequestOptions{Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	options := timestamp.IssueOptions{Policy: policy, SerialNumber: big.NewInt(1), GenTime: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), ExtraCertificates: certificates}
	allocated = allocatedDuring(t, func() error {
		_, err := timestamp.WriteResponse(t.Context(), io.Discard, query.DER(), key, tsaDER, options)
		return err
	})
	t.Logf("timestamp issuance with %d certificate bytes: %d allocated", total, allocated)
	if allocated > uint64(total)+(256<<10) {
		t.Fatalf("timestamp writer buffered complete response: %d allocated", allocated)
	}
	var wire bytes.Buffer
	if _, err := timestamp.WriteResponse(t.Context(), &wire, query.DER(), key, tsaDER, options); err != nil {
		t.Fatal(err)
	}
	response, err := timestamp.ParseResponseReader(t.Context(), bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	token, err := timestamp.ParseTokenReader(t.Context(), bytes.NewReader(response.TokenDER()))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("InfoReleasesCertificateBag", func(t *testing.T) {
		raw := token.DER()
		retained := retainedHeapDuring(t, func() any {
			results := make([]timestamp.Info, 8)
			for i := range results {
				var err error
				results[i], err = timestamp.InspectToken(t.Context(), raw)
				if err != nil || !results[i].Policy().Equal(policy) {
					t.Fatal("timestamp info changed", err)
				}
			}
			return results
		})
		t.Logf("eight timestamp info values: %d retained heap bytes", retained)
		if retained > 2<<20 {
			t.Fatalf("timestamp info retained discarded DER containers: %d bytes", retained)
		}
	})
	verifier, err := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{rootDER}}, AllowedPolicies: []asn1.ObjectIdentifier{policy}, AllowUncheckedRevocation: true})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(t.Context(), token, timestamp.Expectation{Imprint: query.Imprint(), Nonce: query.Nonce(), Policy: policy}, options.GenTime, pki.Evidence{})
	if err != nil || verified.Token() != token {
		t.Fatal("public token verification", err)
	}
	var encoded bytes.Buffer
	if n, err := verified.Token().WriterTo(t.Context()).WriteTo(&encoded); err != nil || n != int64(token.Size()) || !bytes.Equal(encoded.Bytes(), response.TokenDER()) {
		t.Fatal("public token writer", n, err)
	}
	payload, err := document.ParseReader(t.Context(), strings.NewReader(`<r ID="payload">`+strings.Repeat(`<item>value</item>`, 1024)+`</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	basic, _, err := xades.SignBasicEnveloped(t.Context(), payload, key, certificate, xades.SignOptions{SignatureMethod: xmldsig.ECDSASHA256, ClaimedSigningTime: options.GenTime})
	if err != nil {
		t.Fatal(err)
	}
	transport := timestamp.TransportFunc(func(ctx context.Context, request []byte) (io.ReadCloser, error) {
		response, err := timestamp.IssueResponse(ctx, request, key, tsaDER, timestamp.IssueOptions{Policy: policy, SerialNumber: big.NewInt(99), GenTime: options.GenTime, ExtraCertificates: [][]byte{rootDER}})
		return io.NopCloser(bytes.NewReader(response)), err
	})
	validation := xades.TimedOptions{TSA: verifier, At: options.GenTime}
	for count := 1; count <= 2; count++ {
		before, err := basic.XML(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		edited, result, err := xades.AddSignatureTimestamp(t.Context(), basic, xmldsig.Signatures(basic)[0], certificate, transport, xades.AddTimestampOptions{Validation: validation, Request: timestamp.RequestOptions{Policy: policy}})
		if err != nil || len(result.Timestamps()) != count {
			t.Fatal("timestamp edit failed", err)
		}
		after, err := basic.XML(t.Context())
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("timestamp edit changed its input snapshot", err)
		}
		if _, err := xades.VerifyTimedEnveloped(t.Context(), edited, xmldsig.Signatures(edited)[0], certificate, validation); err != nil {
			t.Fatal("edited timestamp/signature failed verification", err)
		}
		basic = edited
	}
}

func TestPublicKeysReleaseSourceCertificates(t *testing.T) {
	identity, rootKey := largeKeyIdentity(t)
	retained := retainedHeapDuring(t, func() any {
		results := make([]crypto.PublicKey, 16)
		for i := range results {
			var err error
			results[i], err = keys.ParsePublic(bytes.Clone(identity.ExtraCertificates[0].Raw), keys.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			actual, err := x509.MarshalPKIXPublicKey(results[i])
			if err != nil {
				t.Fatal(err)
			}
			expected, err := x509.MarshalPKIXPublicKey(rootKey.Public())
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatal("extracted public key changed", err)
			}
		}
		return results
	})
	t.Logf("sixteen extracted public keys: %d retained heap bytes", retained)
	if retained > 2<<20 {
		t.Fatalf("public keys retained source certificates: %d bytes", retained)
	}
}

func TestPKIWorkingStorage(t *testing.T) {
	identity, rootKey := largeKeyIdentity(t)
	root := identity.ExtraCertificates[0]
	rootInput, leafInput := bytes.Clone(root.Raw), bytes.Clone(identity.Certificate.Raw)
	var verifier *pki.Verifier
	allocated := allocatedDuring(t, func() error {
		var err error
		verifier, err = pki.NewVerifier(pki.Config{Roots: [][]byte{rootInput}})
		return err
	})
	t.Logf("PKI trust snapshot: %d DER bytes, %d allocated", len(rootInput), allocated)
	if allocated > uint64(len(rootInput))+(128<<10) {
		t.Fatal("trust snapshot duplicated DER", allocated)
	}
	allocated = allocatedDuring(t, func() error {
		_, err := verifier.WithIntermediateCertificates([][]byte{leafInput})
		return err
	})
	if allocated > uint64(len(leafInput))+(128<<10) {
		t.Fatal("replacement intermediates duplicated DER", allocated)
	}
	now := root.NotBefore.Add(time.Hour)
	var result *pki.Result
	allocated = allocatedDuring(t, func() error {
		var err error
		result, _, err = verifier.Verify(t.Context(), leafInput, now, pki.Evidence{})
		return err
	})
	t.Logf("PKI verification: %d leaf bytes, %d allocated", len(leafInput), allocated)
	if allocated > uint64(len(leafInput))+(256<<10) {
		t.Fatal("result recopied owned chain", allocated)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{9}, 2<<20)}}}, root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	withCRL, err := pki.NewVerifier(pki.Config{Roots: [][]byte{rootInput}, Revocation: pki.RequireCRL})
	if err != nil {
		t.Fatal(err)
	}
	var crlResult *pki.Result
	allocated = allocatedDuring(t, func() error {
		var err error
		crlResult, _, err = withCRL.Verify(t.Context(), leafInput, now, pki.Evidence{CRLs: [][]byte{crl}})
		return err
	})
	t.Logf("PKI verification with %d CRL bytes: %d allocated", len(crl), allocated)
	// Verification owns one leaf snapshot and retains one immutable original
	// CRL source for authenticated evidence. Parsed extensions and signer
	// candidates must not introduce any further input-sized copies.
	if allocated > uint64(len(leafInput)+len(crl))+(256<<10) {
		t.Fatal("CRL verification duplicated source or candidate DER", allocated)
	}
	facts := crlResult.Evidence()
	if len(facts) != 1 || facts[0].AuthenticationStatus() != pki.Valid {
		t.Fatal("missing authenticated CRL source")
	}
	originalCRL := bytes.Clone(crl)
	clear(crl)
	if !bytes.Equal(facts[0].DER(), originalCRL) {
		t.Fatal("authenticated evidence retained caller-owned CRL")
	}
	ownedCRL := facts[0].DER()
	clear(ownedCRL)
	if !bytes.Equal(facts[0].DER(), originalCRL) {
		t.Fatal("evidence getter exposes immutable source")
	}
	clear(rootInput)
	clear(leafInput)
	chain := result.ChainDER()
	if len(chain) != 2 || !bytes.Equal(chain[0], identity.Certificate.Raw) || !bytes.Equal(chain[1], root.Raw) {
		t.Fatal("verification retained caller-owned DER")
	}
	clear(chain[0])
	if !bytes.Equal(result.ChainDER()[0], identity.Certificate.Raw) {
		t.Fatal("chain getter exposes immutable result")
	}
	if _, err := result.PublicKey(); err != nil {
		t.Fatal(err)
	}
}

func TestKeyMaterialWorkingStorage(t *testing.T) {
	identity, rootKey := largeKeyIdentity(t)
	root := identity.ExtraCertificates[0]
	allocated := allocatedDuring(t, func() error {
		_, err := keys.ParsePublic(identity.Certificate.Raw, keys.Limits{})
		return err
	})
	if allocated > 128<<10 {
		t.Fatal("public key extraction copied complete certificate", allocated)
	}
	pin, err := pki.NewKeyPin(identity.PrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	allocated = allocatedDuring(t, func() error { return pin.MatchCertificate(identity.Certificate.Raw) })
	if allocated > 128<<10 {
		t.Fatal("pin matching copied complete certificate", allocated)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: root.NotBefore, NextUpdate: root.NotAfter, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{9}, 2<<20)}}}, root, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})
	encoded = bytes.ReplaceAll(encoded, []byte{'\n'}, []byte{' ', '\t', '\r', '\n'})
	allocated = allocatedDuring(t, func() error {
		parsed, err := keys.ParseCRL(encoded, keys.Limits{})
		if err == nil && !bytes.Equal(parsed.Raw, crl) {
			return errors.New("PEM CRL changed")
		}
		return err
	})
	t.Logf("PEM parsing: %d decoded CRL bytes, %d allocated", len(crl), allocated)
	if allocated > uint64(len(crl))+(256<<10) {
		t.Fatal("PEM parsing buffered encoded text", allocated)
	}
	allocated = allocatedDuring(t, func() error {
		parsed, err := keys.ParseCRL(encoded, keys.Limits{MaxCRLBytes: len(crl) - 1})
		if parsed != nil || !errors.Is(err, keys.ErrLimit) {
			return errors.New("decoded budget was not enforced")
		}
		return nil
	})
	if allocated > 64<<10 {
		t.Fatal("oversized PEM allocated decoded output", allocated)
	}
}

func TestPKCS12WorkingStorage(t *testing.T) {
	identity, _ := largeKeyIdentity(t)
	password := []byte("container memory test")
	options := keys.PKCS12Options{Encryption: keys.EncryptionOptions{Hash: crypto.SHA256, KeyBits: 256, Iterations: 1000}}
	total := len(identity.Certificate.Raw) + len(identity.ExtraCertificates[0].Raw)
	allocated := allocatedDuring(t, func() error {
		_, err := keys.WritePKCS12(t.Context(), io.Discard, identity, password, options, keys.Limits{})
		return err
	})
	t.Logf("PKCS12 writer: %d certificate bytes, %d allocated", total, allocated)
	if allocated > uint64(2*total)+(256<<10) {
		t.Fatal("PKCS12 writer assembled complete intermediate DER", allocated)
	}
	var wire []byte
	allocated = allocatedDuring(t, func() error {
		var err error
		wire, err = keys.MarshalPKCS12(t.Context(), identity, password, options, keys.Limits{})
		return err
	})
	if allocated > uint64(3*total)+(256<<10) {
		t.Fatal("PKCS12 byte export recopied complete PFX", allocated)
	}
	allocated = allocatedDuring(t, func() error {
		parsed, err := keys.ParsePKCS12(t.Context(), wire, password, keys.Limits{})
		if err == nil && (!bytes.Equal(parsed.Certificate.Raw, identity.Certificate.Raw) || len(parsed.ExtraCertificates) != 1 || !bytes.Equal(parsed.ExtraCertificates[0].Raw, identity.ExtraCertificates[0].Raw)) {
			return errors.New("PKCS12 identity changed")
		}
		return err
	})
	t.Logf("PKCS12 import: %d container bytes, %d allocated", len(wire), allocated)
	if allocated > uint64(2*total)+(256<<10) {
		t.Fatal("PKCS12 import copied its encoded input", allocated)
	}
}

func TestProtectedKeyWriters(t *testing.T) {
	key, certificate := nativeIOSigner(t)
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	identity := keys.PKCS12Identity{PrivateKey: key, Certificate: cert}
	password := []byte("public writer password")
	options := keys.EncryptionOptions{Iterations: 1000}
	for _, tc := range []struct {
		name               string
		container, classic bool
	}{
		{"pkcs8", false, false},
		{"pkcs12-pbmac1", true, false},
		{"pkcs12-classic", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write := func(ctx context.Context, dst io.Writer, limits keys.Limits) (int64, error) {
				if tc.container {
					return keys.WritePKCS12(ctx, dst, identity, password, keys.PKCS12Options{Encryption: options, ClassicMAC: tc.classic}, limits)
				}
				return keys.WriteEncryptedPrivate(ctx, dst, key, password, options, limits)
			}
			var wire bytes.Buffer
			if n, err := write(t.Context(), &wire, keys.Limits{}); err != nil || n != int64(wire.Len()) {
				t.Fatal(n, err)
			}
			if tc.container {
				parsed, err := keys.ParsePKCS12(t.Context(), wire.Bytes(), password, keys.Limits{})
				if err != nil || !bytes.Equal(parsed.Certificate.Raw, certificate) {
					t.Fatal(err)
				}
			} else if _, err := keys.ParseEncryptedPrivate(t.Context(), wire.Bytes(), password, keys.Limits{}); err != nil {
				t.Fatal(err)
			}
			failure := errors.New("destination failed")
			if n, err := write(t.Context(), &prefixFailure{remaining: 128, failure: failure}, keys.Limits{}); n != 128 || !errors.Is(err, failure) {
				t.Fatal("partial write", n, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			sink := &streamingSink{afterWrite: cancel}
			if n, err := write(ctx, sink, keys.Limits{}); n != int64(sink.bytes) || n > 32<<10 || !errors.Is(err, context.Canceled) {
				t.Fatal("write cancellation", n, err)
			}
			cancel()
			wire.Reset()
			if n, err := write(t.Context(), &wire, keys.Limits{MaxContainerBytes: 1}); n != 0 || wire.Len() != 0 || !errors.Is(err, keys.ErrLimit) {
				t.Fatal("pre-output budget", n, err)
			}
		})
	}
}

func TestKeyInfoCertificateWorkingStorage(t *testing.T) {
	identity, _ := largeKeyIdentity(t)
	certificate := identity.ExtraCertificates[0].Raw
	encoded := base64.StdEncoding.EncodeToString(certificate)
	const header = `<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`
	doc, err := document.ParseReader(t.Context(), strings.NewReader(header+`<ds:X509Data><ds:X509Certificate>`+encoded+`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var result *keyinfo.Result
	allocated := allocatedDuring(t, func() error {
		var err error
		result, err = keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{})
		return err
	})
	t.Logf("KeyInfo inline: %d DER bytes, %d allocated", len(certificate), allocated)
	if allocated > uint64(len(certificate))+(128<<10) {
		t.Fatal("KeyInfo recopied encoded text or owned DER", allocated)
	}
	candidate := result.Candidates()[0]
	owned := candidate.CertificateDER()
	owned[0] ^= 1
	group := result.X509Groups()[0].CertificatesDER()
	group[0][0] ^= 1
	if !bytes.Equal(candidate.CertificateDER(), certificate) || !bytes.Equal(result.X509Groups()[0].CertificatesDER()[0], certificate) {
		t.Fatal("mutable getters changed private certificate storage")
	}
	allocated = allocatedDuring(t, func() error {
		got, err := keyinfo.Parse(t.Context(), doc, doc.Root(), keyinfo.Options{Limits: keyinfo.Limits{MaxBlobBytes: len(certificate) - 1}})
		if got != nil || !errors.Is(err, keyinfo.ErrLimit) {
			return errors.New("KeyInfo decoded budget lost")
		}
		return nil
	})
	if allocated > 64<<10 {
		t.Fatal("oversized certificate allocated before limit check", allocated)
	}
	for _, encodedSource := range []bool{false, true} {
		t.Run(strconv.FormatBool(encodedSource), func(t *testing.T) {
			transform := ""
			if encodedSource {
				transform = `<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms>`
			}
			method := `<ds:RetrievalMethod URI="urn:stream:certificate" Type="` + keyinfo.RawX509Certificate + `">` + transform + `</ds:RetrievalMethod>`
			local, err := document.ParseReader(t.Context(), strings.NewReader(header+method+method+`</ds:KeyInfo>`), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			allocated := allocatedDuring(t, func() error {
				opened, closed := 0, 0
				resolver := resource.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
					opened++
					var src io.Reader = bytes.NewReader(certificate)
					if encodedSource {
						src = strings.NewReader(encoded)
					}
					return &trackedInput{Reader: src, close: func() error { closed++; return nil }}, nil
				})
				result, err := keyinfo.Parse(t.Context(), local, local.Root(), keyinfo.Options{External: &keyinfo.ExternalResources{Resolver: resolver, AllowedURIs: []string{"urn:stream:certificate"}}})
				if err == nil && (opened != 1 || closed != 1 || len(result.Candidates()) != 2) {
					return errors.New("certificate resource cache or lifecycle changed")
				}
				return err
			})
			if allocated > uint64(len(certificate))+(128<<10) {
				t.Fatal("external certificate duplicated input or cached DER", allocated)
			}
		})
	}
}

func TestXMLEncryptionWorkingStorage(t *testing.T) {
	const size = 1 << 20
	plaintext := bytes.Repeat([]byte("x"), size)
	secret := bytes.Repeat([]byte{9}, 32)
	for _, asXML := range []bool{false, true} {
		t.Run(strconv.FormatBool(asXML), func(t *testing.T) {
			doc, err := document.ParseReader(t.Context(), io.MultiReader(strings.NewReader("<r>"), bytes.NewReader(plaintext), strings.NewReader("</r>")), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			encrypt := func() (*document.Document, error) {
				if asXML {
					return xmlenc.EncryptDocumentWithKey(t.Context(), doc, secret, xmlenc.SymmetricOptions{})
				}
				return xmlenc.EncryptBytesWithKey(t.Context(), plaintext, secret, xmlenc.SymmetricOptions{})
			}
			encrypted, err := encrypt()
			if err != nil {
				t.Fatal(err)
			}
			wire, err := encrypted.XML(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			baseline := allocatedDuring(t, func() error {
				_, err := document.ParseReader(t.Context(), bytes.NewReader(wire), document.DefaultLimits())
				return err
			})
			allocation := allocatedDuring(t, func() error { _, err := encrypt(); return err })
			t.Logf("encryption XML=%v: %d allocated, %d result-parser baseline", asXML, allocation, baseline)
			if allocation > baseline+size+(256<<10) {
				t.Fatal("encryption retained extra plaintext/Base64 buffers", allocation, baseline)
			}
			if !bytes.Equal(plaintext, bytes.Repeat([]byte("x"), size)) {
				t.Fatal("encryption modified caller input")
			}
		})
	}
}

func TestExternalCiphertextWorkingStorageAndAuthentication(t *testing.T) {
	const size = 4 << 20
	secret := bytes.Repeat([]byte{11}, 32)
	plaintext := bytes.Repeat([]byte("p"), size)
	encrypted, err := xmlenc.EncryptBytesWithKey(t.Context(), plaintext, secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const uri = "urn:stream:ciphertext"
	external, _, ciphertext, err := xmlenc.ExternalizeCiphertext(t.Context(), encrypted, encrypted.Root(), uri)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := external.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, useBase64 := range []bool{false, true} {
		t.Run(strconv.FormatBool(useBase64), func(t *testing.T) {
			doc := external
			encoded := base64.StdEncoding.EncodeToString(ciphertext)
			if useBase64 {
				text := strings.Replace(string(wire), `URI="`+uri+`"></xenc:CipherReference>`, `URI="`+uri+`"><xenc:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"></ds:Transform></xenc:Transforms></xenc:CipherReference>`, 1)
				doc, err = document.ParseReader(t.Context(), strings.NewReader(text), document.DefaultLimits())
				if err != nil || text == string(wire) {
					t.Fatal("Base64 reference fixture", err)
				}
			}
			closed := 0
			resolver := resource.ResolverFunc(func(context.Context, string) (io.ReadCloser, error) {
				var src io.Reader = bytes.NewReader(ciphertext)
				if useBase64 {
					src = strings.NewReader(encoded)
				}
				return &trackedInput{Reader: src, close: func() error { closed++; return nil }}, nil
			})
			options := xmlenc.SymmetricOptions{Data: xmlenc.Options{External: &xmlenc.ExternalCipherReference{URI: uri, Resolver: resolver}}}
			allocated := allocatedDuring(t, func() error {
				got, err := xmlenc.DecryptBytesWithKey(t.Context(), doc, secret, options)
				if err == nil && !bytes.Equal(got, plaintext) {
					return errors.New("external plaintext changed")
				}
				return err
			})
			t.Logf("external Base64=%v: %d ciphertext bytes, %d allocated", useBase64, len(ciphertext), allocated)
			if allocated > uint64(2*len(ciphertext))+(256<<10) || closed != 3 {
				t.Fatal("external collection recopied growing prefixes or leaked reader", allocated, closed)
			}
			ciphertext[len(ciphertext)-1] ^= 1
			encoded = base64.StdEncoding.EncodeToString(ciphertext)
			if got, err := xmlenc.DecryptBytesWithKey(t.Context(), doc, secret, options); got != nil || !errors.Is(err, xmlenc.ErrDecrypt) {
				t.Fatal("unauthenticated plaintext returned", len(got), err)
			}
			ciphertext[len(ciphertext)-1] ^= 1
		})
	}
}

func TestXMLReplacementUsesResultParserStorage(t *testing.T) {
	secret := bytes.Repeat([]byte{13}, 32)
	raw := `<r xmlns="urn:root"><secret>private</secret>` + strings.Repeat(`<v a="x">kept</v>`, 5000) + `</r>`
	source, err := document.ParseReader(t.Context(), strings.NewReader(raw), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	encrypted, selected, err := xmlenc.EncryptElementWithKey(t.Context(), source, source.Root().Children()[0], secret, xmlenc.SymmetricOptions{})
	if err != nil {
		t.Fatal(err)
	}
	baseline := allocatedDuring(t, func() error {
		_, err := document.ParseReader(t.Context(), strings.NewReader(raw), document.DefaultLimits())
		return err
	})
	allocated := allocatedDuring(t, func() error {
		_, restored, err := xmlenc.DecryptElementWithKey(t.Context(), encrypted, selected, secret, xmlenc.SymmetricOptions{})
		if err == nil && restored.Text() != "private" {
			return errors.New("restored selection changed")
		}
		return err
	})
	t.Logf("replacement: %d allocated, %d result-parser baseline", allocated, baseline)
	if allocated > baseline+(256<<10) {
		t.Fatal("replacement cloned retained subtrees", allocated, baseline)
	}
	unchanged, err := source.XML(t.Context())
	if err != nil || string(unchanged) != raw {
		t.Fatal("original snapshot changed", err)
	}
}

func largeKeyIdentity(t *testing.T) (keys.PKCS12Identity, crypto.Signer) {
	t.Helper()
	key, _ := nativeIOSigner(t)
	rootKey, _ := nativeIOSigner(t)
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "large material root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{7}, 512<<10)}}}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "large material leaf"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: bytes.Repeat([]byte{8}, 256<<10)}}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return keys.PKCS12Identity{PrivateKey: key, Certificate: leaf, ExtraCertificates: []*x509.Certificate{root}}, rootKey
}
