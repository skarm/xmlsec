// Command evidenceprobe is a private interoperability test adapter.
// Offline test harness only. Private key paths are caller-controlled temp files.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/cms"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/pki"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xades"
	"github.com/skarm/xmlsec/xmldsig"
)

const outputFileMode = 0o600

const (
	probeDefaultHashBits  = 256
	probeDefaultTime      = "2026-10-08T12:00:00Z"
	probeDefaultTSAPolicy = "1.2.3.4.1"
)

func main() {
	mode := flag.String("mode", "", "operation")
	input := flag.String("in", "", "input")
	out := flag.String("out", "", "output")
	kp := flag.String("key", "", "PKCS8 PEM")
	cert := flag.String("cert", "", "DER certificate")
	issuer := flag.String("issuer", "", "DER issuer")
	root := flag.String("root", "", "DER root")
	crl := flag.String("crl", "", "CRL")
	data := flag.String("data", "", "content")
	req := flag.String("request", "", "request")
	det := flag.Bool("detached", false, "detached CMS")
	pss := flag.Bool("pss", false, "RSA-PSS")
	hash := flag.Int("hash", probeDefaultHashBits, "hash bits")
	at := flag.String("at", probeDefaultTime, "time")
	status := flag.String("status", string(pki.OCSPGood), "OCSP status")
	nonceHex := flag.String("nonce", "", "nonce hex")
	policyText := flag.String("policy", probeDefaultTSAPolicy, "TSA policy")
	alg := flag.String("alg", c14n.Exclusive, "archive canonicalization")
	token := flag.String("token", "", "archive token CMS")

	flag.Parse()

	h, e := hashFromBits(*hash)
	must(e)

	t, e := time.Parse(time.RFC3339Nano, *at)
	must(e)

	policy := make(asn1.ObjectIdentifier, 0, strings.Count(*policyText, ".")+1)

	for s := range strings.SplitSeq(*policyText, ".") {
		n, e := strconv.Atoi(s)
		must(e)

		policy = append(policy, n)
	}

	nonce, e := hex.DecodeString(*nonceHex)
	must(e)

	ctx := context.Background()

	key, e := loadSigner(*kp)
	must(e)

	var output []byte

	tsa := func() *timestamp.Verifier {
		v, e := timestamp.NewVerifier(timestamp.Config{PKI: pki.Config{Roots: [][]byte{read(*root)}, Revocation: pki.RequireCRL}, AllowedPolicies: []asn1.ObjectIdentifier{policy}, ClockSkew: time.Minute})
		must(e)

		return v
	}

	switch *mode {
	case "cms-sign":
		output, e = cms.Sign(ctx, read(*data), []cms.Signer{{Key: key, CertificateDER: read(*cert), Hash: h, RSAPSS: *pss}}, cms.SignOptions{Detached: *det})
	case "cms-verify":
		s, err := cms.Parse(ctx, read(*input), cms.DefaultLimits())
		must(err)

		o := cms.VerifyOptions{ExpectedContentType: cms.DataOID()}

		if *det {
			b := read(*data)
			o.DetachedContent = &b
		}

		r, err := s.Verify(ctx, [][]byte{read(*cert)}, o)
		must(err)

		output = r.Content()
	case "ocsp-request":
		output, e = pki.CreateOCSPRequest(read(*cert), read(*issuer), h, nonce)
	case "ocsp-issue":
		output, e = pki.CreateOCSPResponse(ctx, read(*req), read(*data), read(*issuer), read(*cert), key, pki.OCSPResponseTemplate{Status: pki.OCSPStatus(*status), ProducedAt: t, ThisUpdate: t.Add(-time.Minute), NextUpdate: t.Add(time.Hour), RevokedAt: t.Add(-time.Hour), Hash: h, RSAPSS: *pss})
	case "ocsp-verify":
		_, report, err := pki.VerifyOCSP(ctx, read(*input), read(*cert), read(*issuer), t, pki.OCSPOptions{ExpectedNonce: nonce})
		e = err

		fmt.Printf("%+v\n", report)
	case "ts-request":
		r, err := timestamp.CreateRequest(ctx, read(*data), timestamp.RequestOptions{Hash: h, Policy: policy})

		e = err
		if err == nil {
			output = r.DER()
		}
	case "ts-issue":
		output, e = timestamp.IssueResponse(ctx, read(*req), key, read(*cert), timestamp.IssueOptions{Policy: policy, SerialNumber: big.NewInt(42), GenTime: t, Hash: h, RSAPSS: *pss, ExtraCertificates: [][]byte{read(*root)}})
	case "ts-verify":
		q, err := timestamp.ParseRequest(read(*req))
		must(err)
		r, err := tsa().VerifyResponse(ctx, read(*input), q, t, pki.Evidence{CRLs: [][]byte{read(*crl)}})

		e = err
		if err == nil {
			output = r.TokenDER()
		}
	case "xades-basic":
		d, err := document.Parse(ctx, read(*data), document.DefaultLimits())
		must(err)

		method := xmldsig.ECDSASHA256

		if key == nil {
			must(errors.New("private key is required"))
			return
		}

		if _, ok := key.Public().(*rsa.PublicKey); ok {
			method = xmldsig.RSASHA256
		}

		d, _, err = xades.SignBasicEnveloped(ctx, d, key, read(*cert), xades.SignOptions{SignatureMethod: method, ClaimedSigningTime: t})
		must(err)

		output, e = d.XML(ctx)
	case "xades-value":
		_, selected := readSignedDocument(ctx, *input)
		value, err := signatureValue(selected)
		must(err)

		var b bytes.Buffer
		must(c14n.WriteElement(ctx, &b, value, c14n.Options{Algorithm: c14n.Exclusive}))
		output = b.Bytes()
	case "xades-attach":
		d, selected := readSignedDocument(ctx, *input)
		r, err := timestamp.ParseResponse(ctx, read(*data))
		must(err)
		d, _, err = xades.AttachSignatureTimestamp(ctx, d, selected, read(*cert), r.TokenDER(), xades.AddTimestampOptions{Validation: xades.TimedOptions{TSA: tsa(), At: t, Evidence: pki.Evidence{CRLs: [][]byte{read(*crl)}}}})
		must(err)

		output, e = d.XML(ctx)
	case "xades-embed", "archive-add", "archive-attach", "archive-verify":
		doc, selected := readSignedDocument(ctx, *input)
		tv, err := xades.NewValidator(xades.ValidatorConfig{SignerPKI: pki.Config{Roots: [][]byte{read(*root)}, Revocation: pki.RequireCRL}, TSA: tsa(), MinimumLevel: xades.LevelLT})
		must(err)

		proof := xades.ValidationEvidence{Signer: pki.Evidence{CRLs: [][]byte{read(*crl)}}, TSA: pki.Evidence{CRLs: [][]byte{read(*crl)}}}

		switch *mode {
		case "xades-embed":
			doc, _, e = tv.EmbedValidationMaterial(ctx, doc, selected, read(*cert), t, proof)
		case "archive-add":
			tr := timestamp.TransportFunc(func(ctx context.Context, q []byte) (io.ReadCloser, error) {
				b, err := timestamp.IssueResponse(ctx, q, key, read(*issuer), timestamp.IssueOptions{Policy: policy, SerialNumber: big.NewInt(99), GenTime: t, ExtraCertificates: [][]byte{read(*root)}})
				if err != nil {
					return nil, err
				}

				return io.NopCloser(bytes.NewReader(b)), nil
			})
			doc, _, e = tv.AddArchiveTimestamp(ctx, doc, selected, read(*cert), t, tr, xades.AddArchiveOptions{Canonicalization: *alg, Request: timestamp.RequestOptions{Policy: policy}})
		case "archive-attach":
			doc, _, e = tv.AttachArchiveTimestamp(ctx, doc, selected, read(*cert), t, read(*token), *alg)
		default:
			r, err := tv.ValidateEnveloped(ctx, doc, selected, read(*cert), t, xades.ValidationEvidence{})
			must(err)

			if r.Level() != xades.LevelLTA {
				must(errors.New("archive level"))
			}

			fmt.Println("archives", len(r.ArchiveTimestamps()))
		}

		must(e)

		if *out != "" {
			output, e = doc.XML(ctx)
		}
	case "xades-verify":
		d, selected := readSignedDocument(ctx, *input)

		_, e = xades.VerifyTimedEnveloped(ctx, d, selected, read(*cert), xades.TimedOptions{TSA: tsa(), At: t, Evidence: pki.Evidence{CRLs: [][]byte{read(*crl)}}})
	default:
		must(errors.New("mode"))
	}

	must(e)

	if *out != "" {
		must(os.WriteFile(*out, output, outputFileMode))
	}

	fmt.Println("OK", *mode)
}

func readSignedDocument(ctx context.Context, path string) (*document.Document, document.Element) {
	doc, err := document.Parse(ctx, read(path), document.DefaultLimits())
	must(err)
	selected, err := singleSignature(doc)
	must(err)

	return doc, selected
}

func singleSignature(doc *document.Document) (document.Element, error) {
	signatures := xmldsig.Signatures(doc)
	if len(signatures) != 1 {
		return document.Element{}, fmt.Errorf("expected one signature, got %d", len(signatures))
	}

	return signatures[0], nil
}

func signatureValue(signature document.Element) (document.Element, error) {
	children := signature.Children()
	if len(children) < 2 || children[0].Name() != (document.Name{Space: xmldsig.Namespace, Local: "SignedInfo"}) || children[1].Name() != (document.Name{Space: xmldsig.Namespace, Local: "SignatureValue"}) {
		return document.Element{}, errors.New("missing SignatureValue after SignedInfo")
	}

	return children[1], nil
}

func must(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func read(p string) []byte {
	b, e := os.ReadFile(p) // #nosec G304 -- The local interoperability harness supplies fixture paths.
	must(e)

	return b
}

func hashFromBits(bits int) (crypto.Hash, error) {
	switch bits {
	case 1:
		return crypto.SHA1, nil
	case 256:
		return crypto.SHA256, nil
	case 384:
		return crypto.SHA384, nil
	case 512:
		return crypto.SHA512, nil
	default:
		return 0, errors.New("hash")
	}
}

func loadSigner(path string) (crypto.Signer, error) {
	if path == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(path) // #nosec G304 -- The local harness selects a private test fixture.
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("PEM")
	}
	defer clear(block.Bytes)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("signer")
	}

	return signer, nil
}
