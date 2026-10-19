package keyinfo

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// KeyFormat selects the XML representation of a public key.
type KeyFormat string

const (
	// XMLKeyValue selects the XML RSAKeyValue or ECKeyValue representation.
	XMLKeyValue KeyFormat = "xml"
	// DERKeyValue selects the DEREncodedKeyValue representation.
	DERKeyValue KeyFormat = "der"
)

// PublicKeyValue supplies a public key and its requested KeyInfo representation.
type PublicKeyValue struct {
	Key crypto.PublicKey
	// Format defaults to XMLKeyValue. Ed25519 requires DERKeyValue explicitly.
	Format KeyFormat
}

// Template supplies key descriptions without establishing identity or trust.
// Supplied blobs and keys must not be mutated concurrently with Build.
type Template struct {
	ID    string
	Names []string
	Keys  []PublicKeyValue
	// Certificates supplies one X509Data group of DER certificates.
	// Ordering establishes neither a chain nor trust.
	Certificates [][]byte
	// KeyInfoReferences supplies URI references; Build checks syntax, not existence.
	KeyInfoReferences []string
}

// Build creates an immutable standalone KeyInfo document. It does not retrieve
// referenced keys or sign anything. Ed25519 uses DEREncodedKeyValue (not an
// invented XML KeyValue format). XMLLimits come from the bounded default profile.
func Build(ctx context.Context, t Template) (*document.Document, error) {
	if ctx == nil {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if t.ID != "" && !tree.NCName(t.ID) {
		return nil, ErrInput
	}

	if len(t.Names)+len(t.Keys)+len(t.Certificates)+len(t.KeyInfoReferences) == 0 {
		return nil, ErrInput
	}

	if len(t.Names) > 32 || len(t.Keys) > 32 || len(t.Certificates) > 32 || len(t.KeyInfoReferences) > 32 {
		return nil, ErrLimit
	}

	root := element(Namespace, "ds", "KeyInfo")

	root.NS = []tree.Namespace{{Prefix: "ds", URI: Namespace}, {Prefix: "dsig11", URI: Namespace11}}
	if t.ID != "" {
		set(root, "Id", t.ID)
	}

	total := 0
	for _, name := range t.Names {
		total += len(name)
		if total > 4<<20 {
			return nil, ErrLimit
		}

		v := element(Namespace, "ds", "KeyName")
		addText(v, name)
		add(root, v)
	}

	if err := buildKeys(ctx, t.Keys, root); err != nil {
		return nil, err
	}

	if returned1, matched := buildCertificates(ctx, &t, &total, root); matched {
		return nil, returned1
	}

	for _, uri := range t.KeyInfoReferences {
		if len(uri) > 8192 {
			return nil, ErrLimit
		}

		if externalURI(uri) && !validExternalURI(uri) {
			return nil, ErrInput
		}

		r := element(Namespace11, "dsig11", nameKeyInfoReference)
		set(r, "URI", uri)
		add(root, r)
	}

	doc := tree.FromNodes([]*tree.Node{root}, document.DefaultLimits())

	return tree.Reparse(ctx, doc, document.DefaultLimits())
}

func element(ns, prefix, local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Name: document.Name{Space: ns, Local: local}, Prefix: prefix}
}

func add(parent, child *tree.Node) {
	child.Parent = parent
	parent.Children = append(parent.Children, child)
}

func set(n *tree.Node, name, value string) {
	n.Attrs = append(n.Attrs, tree.Attribute{Name: document.Name{Local: name}, Value: value})
}
func addText(n *tree.Node, value string) { add(n, &tree.Node{Kind: tree.TextNode, Data: value}) }
func blob(ctx context.Context, n *tree.Node, ns, prefix, local string, b []byte) error {
	encoded, err := tree.EncodeBase64(ctx, b)
	if err != nil {
		return err
	}

	v := element(ns, prefix, local)
	addText(v, encoded)
	add(n, v)

	return nil
}

func buildCertificates(ctx context.Context, t *Template, total *int, root *tree.Node) (returned1 error, matched bool) {
	if len(t.Certificates) > 0 {
		xd := element(Namespace, "ds", nameX509Data)

		for _, der := range t.Certificates {
			(*total) += len(der)
			if len(der) > 1<<20 || (*total) > 4<<20 {
				return ErrLimit, true
			}

			if _, err := x509.ParseCertificate(der); err != nil {
				return fmt.Errorf("%w: certificate: %w", ErrInput, err), true
			}

			if err := blob(ctx, xd, Namespace, "ds", "X509Certificate", der); err != nil {
				return err, true
			}
		}

		add(root, xd)
	}

	return
}

func buildKeys(ctx context.Context, keys []PublicKeyValue, root *tree.Node) error {
	for _, value := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := validateKey(value.Key, 8192); err != nil {
			return err
		}

		node, err := buildPublicKey(ctx, value)
		if err != nil {
			return err
		}

		add(root, node)
	}

	return nil
}

func buildPublicKey(ctx context.Context, value PublicKeyValue) (*tree.Node, error) {
	switch value.Format {
	case DERKeyValue:
		der, err := x509.MarshalPKIXPublicKey(value.Key)
		if err != nil {
			return nil, err
		}

		node := element(Namespace11, "dsig11", nameDEREncodedKeyValue)

		encoded, err := tree.EncodeBase64(ctx, der)
		if err != nil {
			return nil, err
		}

		addText(node, encoded)

		return node, nil
	case "", XMLKeyValue:
		node := element(Namespace, "ds", "KeyValue")

		child, err := buildXMLKey(ctx, value.Key)
		if err != nil {
			return nil, err
		}

		add(node, child)

		return node, nil
	default:
		return nil, fmt.Errorf("%w: key format", ErrPolicy)
	}
}

func buildXMLKey(ctx context.Context, key crypto.PublicKey) (*tree.Node, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		node := element(Namespace, "ds", nameRSAKeyValue)
		if err := blob(ctx, node, Namespace, "ds", "Modulus", k.N.Bytes()); err != nil {
			return nil, err
		}

		if err := blob(ctx, node, Namespace, "ds", "Exponent", big.NewInt(int64(k.E)).Bytes()); err != nil {
			return nil, err
		}

		return node, nil
	case *ecdsa.PublicKey:
		node := element(Namespace11, "dsig11", nameECKeyValue)
		curve := element(Namespace11, "dsig11", "NamedCurve")
		set(curve, "URI", curveURI(k.Curve))
		add(node, curve)

		point, err := k.Bytes()
		if err != nil {
			return nil, ErrKey
		}

		if err := blob(ctx, node, Namespace11, "dsig11", "PublicKey", point); err != nil {
			return nil, err
		}

		return node, nil
	case ed25519.PublicKey:
		return nil, fmt.Errorf("%w: Ed25519 requires DERKeyValue", ErrUnsupported)
	default:
		return nil, ErrUnsupported
	}
}
