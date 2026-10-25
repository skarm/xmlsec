package xmlenc

import (
	"context"
	"crypto/aes"
	"crypto/des" // #nosec G502 -- Explicit legacy XMLENC key-wrap policy.
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// KeyGraphReference identifies the exact data or encrypted/derived key using a
// generated key. Key selects KeyReference; otherwise DataReference is emitted.
// URI grants no permission to resolve the referenced resource.
type KeyGraphReference struct {
	URI string
	Key bool
}

// EncryptedKeyOptions controls generation of standalone EncryptedKey. Algorithm
// must equal the supplied recipient's explicit Algorithm. Empty names/IDs omit
// their metadata; no container protocol, key store or external I/O is created.
type EncryptedKeyOptions struct {
	Algorithm                     string
	OAEP                          *OAEPParameters
	AllowLegacy                   bool
	ID, Recipient, CarriedKeyName string
	References                    []KeyGraphReference
	// Properties is an optional EncryptionProperties document, copied into output.
	Properties *document.Document
}

// EncryptKey wraps rawKey into standalone EncryptedKey. The recipient supplies
// exactly one RSA PublicKey or symmetric Secret; Decrypter is never accepted.
// Raw keys are 16/24/32 bytes. TripleDES wrap accepts only a 24-byte TripleDES
// key under explicit legacy policy and adjusts its DES parity as RFC3217 requires.
func EncryptKey(ctx context.Context, rawKey []byte, recipient KeyGraphKey, options EncryptedKeyOptions) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !sessionKeySize(len(rawKey)) || recipient.Algorithm == "" || options.Algorithm != recipient.Algorithm || recipient.Decrypter != nil || len(recipient.Name) > 1024 || !utf8.ValidString(recipient.Name) {
		return nil, ErrPolicy
	}

	root := encryptedElement("EncryptedKey")
	if err := graphGeneratedMetadata(root, options.ID, options.Recipient); err != nil {
		return nil, err
	}

	method := encryptedElement("EncryptionMethod")
	setAttribute(method, "Algorithm", options.Algorithm)
	appendChild(root, method)

	wrapped, info, err := graphGenerateKey(ctx, recipient, rawKey, options, method)
	if err != nil {
		return nil, err
	}
	defer clear(wrapped)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if info != nil {
		appendChild(root, info)
	} else if recipient.Name != "" {
		info := newElement(SignatureNamespace, "ds", "KeyInfo")
		name := newElement(SignatureNamespace, "ds", "KeyName")
		appendChild(name, &tree.Node{Kind: tree.TextNode, Data: recipient.Name})
		appendChild(info, name)
		appendChild(root, info)
	}

	data, err := encodeCipherData(ctx, wrapped)
	if err != nil {
		return nil, err
	}

	appendChild(root, data)

	if options.Properties != nil {
		if options.Properties.Root().Name() != elementName(Namespace, "EncryptionProperties") || checkGraphProperties(options.Properties.Root()) != nil {
			return nil, ErrFormat
		}

		root.Children = append(root.Children, tree.Root(options.Properties))
	}

	if err := graphAppendReferences(root, options.References); err != nil {
		return nil, err
	}

	if len(options.CarriedKeyName) > 1024 || !utf8.ValidString(options.CarriedKeyName) {
		return nil, ErrPolicy
	}

	if options.CarriedKeyName != "" {
		name := encryptedElement("CarriedKeyName")
		appendChild(name, &tree.Node{Kind: tree.TextNode, Data: options.CarriedKeyName})
		appendChild(root, name)
	}

	return graphGeneratedDocument(ctx, root)
}

func graphGenerateKey(ctx context.Context, recipient KeyGraphKey, raw []byte, options EncryptedKeyOptions, method *tree.Node) ([]byte, *tree.Node, error) {
	if recipient.ECDHPublicKey == nil {
		if recipient.ECDHRecipient != nil || recipient.ECDH != nil {
			return nil, nil, ErrPolicy
		}

		wrapped, err := graphWrapMaterial(recipient, raw, options, method)

		return wrapped, nil, err
	}

	if recipient.PublicKey != nil || recipient.Decrypter != nil || recipient.ECDHRecipient != nil || len(recipient.Secret) != 0 || options.OAEP != nil {
		return nil, nil, ErrPolicy
	}

	agreement := ECDHOptions{}
	if recipient.ECDH != nil {
		agreement = *recipient.ECDH
	}

	if agreement.Data != (Options{}) || agreement.KeyAlgorithm != "" && agreement.KeyAlgorithm != recipient.Algorithm || agreement.RecipientKeyName != "" && agreement.RecipientKeyName != recipient.Name {
		return nil, nil, ErrPolicy
	}

	agreement.KeyAlgorithm, agreement.RecipientKeyName = recipient.Algorithm, recipient.Name

	profile, err := ecdhEncryptProfile(ctx, recipient.ECDHPublicKey, agreement)
	if err != nil {
		return nil, nil, err
	}

	wrapped, err := profile.transport.wrap(raw)

	return wrapped, profile.transport.keyInfo, err
}

func graphWrapMaterial(recipient KeyGraphKey, rawKey []byte, options EncryptedKeyOptions, method *tree.Node) ([]byte, error) {
	var (
		wrapped []byte
		err     error
	)

	switch {
	case rsaOAEPAlgorithm(options.Algorithm):
		if len(recipient.Secret) != 0 || validateRSAKey(recipient.PublicKey) != nil {
			return nil, ErrPolicy
		}

		parameters, normalizeErr := normalizeOAEP(options.OAEP)
		if normalizeErr != nil || parameters.Algorithm != options.Algorithm {
			return nil, errors.Join(ErrPolicy, normalizeErr)
		}
		defer clear(parameters.Label)

		encodeOAEP(method, parameters)
		wrapped, err = rsa.EncryptOAEPWithOptions(rand.Reader, recipient.PublicKey, rawKey, &rsa.OAEPOptions{Hash: parameters.Hash, MGFHash: parameters.MGFHash, Label: parameters.Label})
	case options.Algorithm == TripleDESKeyWrap:
		if recipient.PublicKey != nil || options.OAEP != nil || !options.AllowLegacy || fips140.Enabled() || len(recipient.Secret) != 24 || len(rawKey) != 24 {
			return nil, ErrPolicy
		}

		block, blockErr := des.NewTripleDESCipher(recipient.Secret) // #nosec G405 -- Explicit legacy policy and FIPS guard above.
		if blockErr != nil {
			return nil, ErrPolicy
		}

		wrapped, err = wrapTripleDES(block, rawKey)
	default:
		if recipient.PublicKey != nil || options.OAEP != nil || graphWrappingKeyBytes(options.Algorithm) == 0 || graphWrappingKeyBytes(options.Algorithm) != len(recipient.Secret) {
			return nil, ErrPolicy
		}

		block, blockErr := aes.NewCipher(recipient.Secret)
		if blockErr != nil {
			return nil, ErrPolicy
		}

		wrapped, err = wrapKey(block, rawKey)
	}

	return wrapped, err
}

// DerivedKeyOptions emits an explicit ConcatKDF context and key relationships.
// The master is identified by an exact application label. This function emits
// metadata only and never resolves, derives, stores or publishes secret material.
type DerivedKeyOptions struct {
	Parameters                                   ConcatKDFParameters
	ID, Recipient, DerivedKeyName, MasterKeyName string
	References                                   []KeyGraphReference
}

// BuildDerivedKey produces a standalone XMLENC1.1 DerivedKey with ConcatKDF.
func BuildDerivedKey(ctx context.Context, options DerivedKeyOptions) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root := newElement(Namespace11, "xenc11", "DerivedKey")
	if err := graphGeneratedMetadata(root, options.ID, options.Recipient); err != nil {
		return nil, err
	}

	method, err := encodeConcatKDFParameters(ctx, options.Parameters)
	if err != nil {
		return nil, err
	}

	appendChild(root, method)

	if err := graphAppendReferences(root, options.References); err != nil {
		return nil, err
	}

	for _, item := range []struct{ name, value string }{{"DerivedKeyName", options.DerivedKeyName}, {"MasterKeyName", options.MasterKeyName}} {
		if len(item.value) > 1024 || !utf8.ValidString(item.value) {
			return nil, ErrPolicy
		}

		if item.value != "" {
			name := newElement(Namespace11, "xenc11", item.name)
			appendChild(name, &tree.Node{Kind: tree.TextNode, Data: item.value})
			appendChild(root, name)
		}
	}

	return graphGeneratedDocument(ctx, root)
}

func graphGeneratedMetadata(root *tree.Node, id, recipient string) error {
	if len(id) > 1024 || id != "" && !tree.NCName(id) || len(recipient) > 1024 || !utf8.ValidString(recipient) {
		return ErrPolicy
	}

	if id != "" {
		setAttribute(root, "Id", id)
	}

	if recipient != "" {
		setAttribute(root, "Recipient", recipient)
	}

	return nil
}

func graphAppendReferences(root *tree.Node, references []KeyGraphReference) error {
	if len(references) > 64 {
		return ErrPolicy
	}

	if len(references) == 0 {
		return nil
	}

	list := encryptedElement("ReferenceList")

	for _, ref := range references {
		if !validGraphReference(ref.URI) {
			return ErrPolicy
		}

		name := "DataReference"
		if ref.Key {
			name = "KeyReference"
		}

		child := encryptedElement(name)
		setAttribute(child, "URI", ref.URI)
		appendChild(list, child)
	}

	appendChild(root, list)

	return nil
}

func graphGeneratedDocument(ctx context.Context, root *tree.Node) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrPolicy
	}

	root.NS = []tree.Namespace{{Prefix: "xenc", URI: Namespace}, {Prefix: "xenc11", URI: Namespace11}, {Prefix: "ds", URI: SignatureNamespace}}
	limits := document.DefaultLimits()
	limits.MaxBytes = 128 << 10

	return tree.ParseProduced(ctx, func(dst io.Writer) error {
		_, err := tree.WriteXMLFragment(ctx, dst, []*tree.Node{root}, limits.MaxBytes)
		return err
	}, limits)
}
