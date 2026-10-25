package xmlenc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
)

const (
	// ECDHES is XML Encryption 1.1 ephemeral-static elliptic-curve agreement.
	ECDHES = Namespace11 + "ECDH-ES"
	// SignatureNamespace11 identifies the ECKeyValue vocabulary.
	SignatureNamespace11 = lexicon.NamespaceDSig11
)

// ECDHOptions selects a static recipient and the expected wire parameters.
// Defaults are AES256GCM and AES256KeyWrap. Agreement establishes no sender
// identity; the application must authenticate the ciphertext and its context.
type ECDHOptions struct {
	// Data selects the data cipher, plaintext and XML limits, and external ciphertext
	// policy.
	Data Options
	// KeyAlgorithm selects AES128KeyWrap, AES192KeyWrap or AES256KeyWrap (default).
	KeyAlgorithm string
	// KDF supplies exact expected ConcatKDF fields, copied without adding values.
	// Nil selects SHA-256, AlgorithmID = 00 || UTF-8(KeyAlgorithm), empty PartyUInfo,
	// and PartyVInfo = 00 || SHA-256(recipient's uncompressed public point).
	// These defaults bind keys/algorithms, not authenticated party identities.
	KDF *ConcatKDFParameters
	// RecipientKeyName is an optional exact untrusted hint, limited to 1024 bytes.
	// If configured, received RecipientKeyInfo must contain the same KeyName.
	// XML hints never select a recipient, algorithm, KDF or trust source.
	// An optional OriginatorKeyInfo/KeyName is validated and ignored.
	RecipientKeyName string
}

// ECDHRecipient provides the application's static private-key operation.
// An *ecdh.PrivateKey implements this interface. Returned secrets are caller-owned
// and must preserve the full 32-, 48- or 66-byte x-coordinate, including leading
// zeros.
type ECDHRecipient interface {
	// PublicKey returns the static recipient public key corresponding to the private operation.
	PublicKey() *ecdh.PublicKey
	// ECDH derives an owned, full-width secret from the supplied peer public key.
	ECDH(*ecdh.PublicKey) ([]byte, error)
}

// ContextECDHRecipient accepts the caller's cancellation and deadline context for
// key agreement. Its returned secret follows ECDHRecipient's ownership and
// full-width encoding contract.
type ContextECDHRecipient interface {
	// PublicKey returns the static recipient public key corresponding to the private operation.
	PublicKey() *ecdh.PublicKey
	// ECDH derives an owned, full-width secret and must honor cancellation.
	ECDH(context.Context, *ecdh.PublicKey) ([]byte, error)
}

// AdaptContextECDHRecipient adapts an explicit contextual provider. XML decrypt
// passes the invocation context; calling the adapter directly uses Background.
func AdaptContextECDHRecipient(provider ContextECDHRecipient) (ECDHRecipient, error) {
	if nilcheck.IsNil(provider) {
		return nil, ErrPolicy
	}

	return &contextECDHAdapter{provider}, nil
}

type contextECDHAdapter struct{ ContextECDHRecipient }

func (a *contextECDHAdapter) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	return a.ContextECDHRecipient.ECDH(context.Background(), peer)
}

func (a *contextECDHAdapter) agreement(ctx context.Context, peer *ecdh.PublicKey) ([]byte, error) {
	return a.ContextECDHRecipient.ECDH(ctx, peer)
}

type contextualAgreement interface {
	agreement(context.Context, *ecdh.PublicKey) ([]byte, error)
}

type agreementParameters struct {
	options     ECDHOptions
	kdf         ConcatKDFParameters
	curve       ecdh.Curve
	curveURI    string
	secretBytes int
	kekBytes    int
}

func agreementProfile(ctx context.Context, recipient *ecdh.PublicKey, options ECDHOptions) (profile, agreementParameters, error) {
	if options.Data.OAEP != nil {
		return profile{}, agreementParameters{}, ErrPolicy
	}

	p, err := normalize(ctx, options.Data)
	if err != nil {
		return profile{}, agreementParameters{}, err
	}

	if recipient == nil {
		return profile{}, agreementParameters{}, ErrPolicy
	}

	curve, uri, width := agreementCurve(recipient.Curve())
	if curve == nil || len(recipient.Bytes()) != 1+2*width {
		return profile{}, agreementParameters{}, ErrPolicy
	}

	if _, err := curve.NewPublicKey(recipient.Bytes()); err != nil {
		return profile{}, agreementParameters{}, ErrPolicy
	}

	if options.KeyAlgorithm == "" {
		options.KeyAlgorithm = AES256KeyWrap
	}

	kekBytes := 0

	switch options.KeyAlgorithm {
	case AES128KeyWrap:
		kekBytes = 16
	case AES192KeyWrap:
		kekBytes = 24
	case AES256KeyWrap:
		kekBytes = 32
	default:
		return profile{}, agreementParameters{}, ErrPolicy
	}

	if !agreementKeyName(options.RecipientKeyName) {
		return profile{}, agreementParameters{}, ErrPolicy
	}

	kdf := ConcatKDFParameters{}

	if options.KDF == nil {
		digest := sha256.Sum256(recipient.Bytes())
		kdf = ConcatKDFParameters{Hash: crypto.SHA256, AlgorithmID: append([]byte{0}, []byte(options.KeyAlgorithm)...), PartyUInfo: []byte{0}, PartyVInfo: append([]byte{0}, digest[:]...)}
	} else {
		kdf = *options.KDF

		fields := []*[]byte{&kdf.AlgorithmID, &kdf.PartyUInfo, &kdf.PartyVInfo, &kdf.SuppPubInfo, &kdf.SuppPrivInfo}
		for _, field := range fields {
			if _, ok := concatFieldBits(*field); !ok {
				return profile{}, agreementParameters{}, ErrPolicy
			}

			*field = bytes.Clone(*field)
		}
	}
	// Check the complete KDF policy before obtaining a private operation.
	probe, err := DeriveConcatKey(ctx, []byte{1}, kekBytes*8, kdf)
	clear(probe)

	if err != nil {
		return profile{}, agreementParameters{}, err
	}

	return p, agreementParameters{options: options, kdf: kdf, curve: curve, curveURI: uri, secretBytes: width, kekBytes: kekBytes}, nil
}

func agreementCurve(curve ecdh.Curve) (ecdh.Curve, string, int) {
	switch curve {
	case ecdh.P256():
		return curve, lexicon.CurveP256, 32
	case ecdh.P384():
		return curve, lexicon.CurveP384, 48
	case ecdh.P521():
		return curve, lexicon.CurveP521, 66
	default:
		return nil, "", 0
	}
}

func agreementKeyName(name string) bool {
	if len(name) > 1024 || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return false
	}

	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == 0xfffe || r == 0xffff {
			return false
		}
	}

	return true
}

func ecdhEncryptProfile(ctx context.Context, recipient *ecdh.PublicKey, options ECDHOptions) (profile, error) {
	p, parameters, err := agreementProfile(ctx, recipient, options)
	if err != nil {
		return profile{}, err
	}

	ephemeral, err := parameters.curve.GenerateKey(rand.Reader)
	if err != nil {
		return profile{}, err
	}

	secret, err := ephemeral.ECDH(recipient)
	if err != nil {
		return profile{}, ErrPolicy
	}
	defer clear(secret)

	kek, err := DeriveConcatKey(ctx, secret, parameters.kekBytes*8, parameters.kdf)
	if err != nil {
		return profile{}, err
	}
	defer clear(kek)

	wrapped, err := keyWrapProfile(ctx, kek, KeyWrapOptions{Data: p.options, KeyAlgorithm: parameters.options.KeyAlgorithm})
	if err != nil {
		return profile{}, err
	}

	metadata, err := encodeAgreement(ctx, ephemeral.PublicKey(), recipient, parameters)
	if err != nil {
		return profile{}, err
	}

	wrapped.transport.keyInfo = metadata

	return wrapped, nil
}

func ecdhDecryptProfile(ctx context.Context, recipient ECDHRecipient, options ECDHOptions) (profile, error) {
	p, err := normalize(ctx, options.Data)
	if err != nil {
		return profile{}, err
	}

	p.transport, err = ecdhDecryptKeyTransport(ctx, recipient, options, p.keyBytes)
	if err != nil {
		return profile{}, err
	}

	return p, nil
}

func ecdhDecryptKeyTransport(ctx context.Context, recipient ECDHRecipient, options ECDHOptions, keyBytes int) (keyTransport, error) {
	if keyBytes != 16 && keyBytes != 24 && keyBytes != 32 {
		return keyTransport{}, ErrPolicy
	}

	if nilcheck.IsNil(recipient) {
		return keyTransport{}, ErrPolicy
	}

	public := recipient.PublicKey()

	_, parameters, err := agreementProfile(ctx, public, options)
	if err != nil {
		return keyTransport{}, err
	}

	var originator *ecdh.PublicKey

	transport := keyTransport{
		algorithm: parameters.options.KeyAlgorithm, wrappedBytes: keyBytes + 8, keyBits: parameters.kekBytes * 8,
		checkKeyInfo: func(ctx context.Context, info document.Element) error {
			var err error

			originator, err = decodeAgreement(ctx, info, public, parameters)

			return err
		},
		unwrap: func(ctx context.Context, wrapped []byte) ([]byte, error) {
			if originator == nil {
				return nil, ErrDecrypt
			}

			var (
				secret []byte
				err    error
			)
			if provider, ok := recipient.(contextualAgreement); ok {
				secret, err = provider.agreement(ctx, originator)
			} else {
				secret, err = recipient.ECDH(originator)
			}
			defer clear(secret)

			if err != nil {
				return nil, err
			}

			if err := ctx.Err(); err != nil {
				return nil, err
			}

			if len(secret) != parameters.secretBytes {
				return nil, ErrDecrypt
			}

			kek, err := DeriveConcatKey(ctx, secret, parameters.kekBytes*8, parameters.kdf)
			if err != nil {
				return nil, err
			}
			defer clear(kek)

			block, err := aes.NewCipher(kek)
			if err != nil {
				return nil, ErrDecrypt
			}

			return unwrapKey(block, wrapped, keyBytes)
		},
	}

	return transport, nil
}

func encodeAgreement(ctx context.Context, originator, recipient *ecdh.PublicKey, p agreementParameters) (*tree.Node, error) {
	kdf, err := encodeConcatKDFParameters(ctx, p.kdf)
	if err != nil {
		return nil, err
	}

	info := newElement(SignatureNamespace, "ds", lexicon.DSigElementKeyInfo)
	method := encryptedElement("AgreementMethod")
	setAttribute(method, "Algorithm", ECDHES)
	appendChild(method, kdf)

	sender := encryptedElement("OriginatorKeyInfo")
	appendChild(sender, agreementKeyValue(originator, p.curveURI))
	appendChild(method, sender)

	receiver := encryptedElement("RecipientKeyInfo")

	if p.options.RecipientKeyName != "" {
		name := newElement(SignatureNamespace, "ds", lexicon.DSigElementKeyName)
		appendChild(name, &tree.Node{Kind: tree.TextNode, Data: p.options.RecipientKeyName})
		appendChild(receiver, name)
	}

	appendChild(receiver, agreementKeyValue(recipient, p.curveURI))
	appendChild(method, receiver)
	appendChild(info, method)

	return info, ctx.Err()
}

func agreementKeyValue(public *ecdh.PublicKey, uri string) *tree.Node {
	value := newElement(SignatureNamespace, "ds", lexicon.DSigElementKeyValue)
	ec := newElement(SignatureNamespace11, "dsig11", "ECKeyValue")
	ec.NS = []tree.Namespace{{Prefix: "dsig11", URI: SignatureNamespace11}}
	curve := newElement(SignatureNamespace11, "dsig11", "NamedCurve")
	setAttribute(curve, "URI", uri)

	point := newElement(SignatureNamespace11, "dsig11", "PublicKey")
	appendChild(point, &tree.Node{Kind: tree.TextNode, Data: base64.StdEncoding.EncodeToString(public.Bytes())})
	appendChild(ec, curve)
	appendChild(ec, point)
	appendChild(value, ec)

	return value
}

func decodeAgreement(ctx context.Context, info document.Element, recipient *ecdh.PublicKey, p agreementParameters) (*ecdh.PublicKey, error) {
	children, err := childElements(info, elementName(Namespace, "AgreementMethod"))
	if err != nil || info.Name() != elementName(SignatureNamespace, lexicon.DSigElementKeyInfo) || !exactAttributes(info) {
		return nil, ErrFormat
	}

	method := children[0]
	if !matchesMethod(method, ECDHES, false) {
		return nil, ErrFormat
	}

	children = method.Children()
	if len(children) < 2 || len(children) > 3 {
		return nil, ErrFormat
	}

	names := []document.Name{elementName(Namespace11, "KeyDerivationMethod"), elementName(Namespace, "OriginatorKeyInfo")}
	if len(children) == 3 {
		names = append(names, elementName(Namespace, "RecipientKeyInfo"))
	}

	children, err = childElements(method, names...)
	if err != nil {
		return nil, err
	}

	actual, err := decodeConcatKDFParameters(ctx, children[0])
	if err != nil {
		return nil, err
	}

	if !sameConcatKDFParameters(actual, p.kdf) {
		return nil, ErrFormat
	}

	sender, err := decodeAgreementKey(ctx, children[1], p)
	if err != nil {
		return nil, err
	}

	if len(children) == 3 {
		if err := checkAgreementRecipient(ctx, children[2], recipient, p); err != nil {
			return nil, err
		}
	} else if p.options.RecipientKeyName != "" {
		return nil, ErrFormat
	}

	return sender, ctx.Err()
}

// Originator names are bounded untrusted hints. Only the required direct point
// is used for agreement; the name never selects a provider or trust source.
func decodeAgreementKey(ctx context.Context, info document.Element, p agreementParameters) (*ecdh.PublicKey, error) {
	if !exactAttributes(info) {
		return nil, ErrFormat
	}

	children := info.Children()
	if len(children) < 1 || len(children) > 2 {
		return nil, ErrFormat
	}

	names := make([]document.Name, len(children))
	for index, child := range children {
		names[index] = child.Name()
	}

	if _, err := childElements(info, names...); err != nil {
		return nil, err
	}

	var point *ecdh.PublicKey

	nameSeen := false

	for _, child := range children {
		switch child.Name() {
		case elementName(SignatureNamespace, lexicon.DSigElementKeyValue):
			if point != nil {
				return nil, ErrFormat
			}

			var err error

			point, err = decodeAgreementKeyValue(ctx, child, p)
			if err != nil {
				return nil, err
			}
		case elementName(SignatureNamespace, lexicon.DSigElementKeyName):
			if nameSeen || !exactAttributes(child) || len(child.Children()) != 0 || !agreementKeyName(child.Text()) {
				return nil, ErrFormat
			}

			nameSeen = true
		default:
			return nil, ErrFormat
		}
	}

	if point == nil {
		return nil, ErrFormat
	}

	return point, ctx.Err()
}

func decodeAgreementKeyValue(ctx context.Context, value document.Element, p agreementParameters) (*ecdh.PublicKey, error) {
	ec, err := childElements(value, elementName(SignatureNamespace11, "ECKeyValue"))
	if err != nil || !exactAttributes(value) || !exactAttributes(ec[0]) {
		return nil, ErrFormat
	}

	fields, err := childElements(ec[0], elementName(SignatureNamespace11, "NamedCurve"), elementName(SignatureNamespace11, "PublicKey"))
	if err != nil || !exactAttributes(fields[0], "URI") || attributeValue(fields[0], "URI") != p.curveURI || len(fields[0].Children()) != 0 || !xmlSpace(fields[0].Text()) || !exactAttributes(fields[1]) || len(fields[1].Children()) != 0 {
		return nil, ErrFormat
	}

	encoded, err := decodeBase64Text(ctx, fields[1], 1+2*p.secretBytes)
	if err != nil {
		return nil, err
	}

	if len(encoded) != 1+2*p.secretBytes || encoded[0] != 4 {
		return nil, ErrFormat
	}

	public, err := p.curve.NewPublicKey(encoded)
	if err != nil {
		return nil, ErrFormat
	}

	return public, ctx.Err()
}

func checkAgreementRecipient(ctx context.Context, info document.Element, recipient *ecdh.PublicKey, p agreementParameters) error {
	if !exactAttributes(info) {
		return ErrFormat
	}

	children := info.Children()
	if len(children) < 1 || len(children) > 2 {
		return ErrFormat
	}

	names := make([]document.Name, len(children))
	for index, child := range children {
		names[index] = child.Name()
	}

	if _, err := childElements(info, names...); err != nil {
		return err
	}

	keySeen, nameSeen := false, false

	for _, child := range children {
		switch child.Name() {
		case elementName(SignatureNamespace, lexicon.DSigElementKeyValue):
			if keySeen {
				return ErrFormat
			}

			keySeen = true

			public, err := decodeAgreementKeyValue(ctx, child, p)
			if err != nil {
				return err
			}

			if !bytes.Equal(public.Bytes(), recipient.Bytes()) {
				return ErrFormat
			}
		case elementName(SignatureNamespace, lexicon.DSigElementKeyName):
			if nameSeen || p.options.RecipientKeyName == "" || !exactAttributes(child) || len(child.Children()) != 0 || child.Text() != p.options.RecipientKeyName {
				return ErrFormat
			}

			nameSeen = true
		default:
			return ErrFormat
		}
	}

	if p.options.RecipientKeyName != "" && !nameSeen {
		return ErrFormat
	}

	return ctx.Err()
}

// EncryptBytesWithECDH uses an explicit static ECDH recipient and AES key wrap.
func EncryptBytesWithECDH(ctx context.Context, plaintext []byte, recipient *ecdh.PublicKey, options ECDHOptions) (*document.Document, error) {
	p, err := ecdhEncryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, err
	}

	return encrypt(ctx, plaintext, p)
}

// DecryptBytesWithECDH uses an explicit static ECDH recipient and AES key wrap.
func DecryptBytesWithECDH(ctx context.Context, doc *document.Document, recipient ECDHRecipient, options ECDHOptions) ([]byte, error) {
	p, err := ecdhDecryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, err
	}

	return decrypt(ctx, doc, p, "")
}

// EncryptDocumentWithECDH has the root-element, NFC and snapshot contracts of EncryptDocument.
func EncryptDocumentWithECDH(ctx context.Context, doc *document.Document, recipient *ecdh.PublicKey, options ECDHOptions) (*document.Document, error) {
	p, err := ecdhEncryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, err
	}

	return encryptDocument(ctx, doc, p)
}

// DecryptDocumentWithECDH has the root-element, NFC and snapshot contracts of DecryptDocument.
func DecryptDocumentWithECDH(ctx context.Context, doc *document.Document, recipient ECDHRecipient, options ECDHOptions) (*document.Document, error) {
	p, err := ecdhDecryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, err
	}

	return decryptDocument(ctx, doc, p)
}

// EncryptElementWithECDH has the selected-node, namespace and budget contracts of EncryptElement.
func EncryptElementWithECDH(ctx context.Context, doc *document.Document, selected document.Element, recipient *ecdh.PublicKey, options ECDHOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := ecdhEncryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptSelected(ctx, doc, node, p)
}

// DecryptElementWithECDH has the selected-node, namespace and budget contracts of DecryptElement.
func DecryptElementWithECDH(ctx context.Context, doc *document.Document, selected document.Element, recipient ECDHRecipient, options ECDHOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := ecdhDecryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptSelected(ctx, doc, node, p)
}

// EncryptContentWithECDH has the selected-node, namespace and budget contracts of EncryptContent.
func EncryptContentWithECDH(ctx context.Context, doc *document.Document, selected document.Element, recipient *ecdh.PublicKey, options ECDHOptions) (*document.Document, document.Element, error) {
	node, err := contentParent(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	p, err := ecdhEncryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return encryptContent(ctx, doc, node, p)
}

// DecryptContentWithECDH has the selected-node, namespace and budget contracts of DecryptContent.
func DecryptContentWithECDH(ctx context.Context, doc *document.Document, selected document.Element, recipient ECDHRecipient, options ECDHOptions) (*document.Document, document.Element, error) {
	node, err := selectedNode(doc, selected)
	if err != nil {
		return nil, document.Element{}, err
	}

	if node.Parent == nil {
		return nil, document.Element{}, ErrFormat
	}

	p, err := ecdhDecryptProfile(ctx, recipient, options)
	if err != nil {
		return nil, document.Element{}, err
	}

	return decryptContent(ctx, doc, node, p)
}
