package keyinfo

import (
	"context"
	"crypto"

	// #nosec G406 -- Explicit bounded legacy compatibility only.
	"crypto/dsa" //nolint:staticcheck // XMLDSig 1.1 requires legacy DSA verification; generation is disabled.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/signature"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// KeyFormat selects the XML representation of a public key.
type KeyFormat string

const (
	// XMLKeyValue selects the XML RSAKeyValue, ECKeyValue or complete DSAKeyValue representation.
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

// RetrievalMethod describes a key resource and its ordered transform chain.
// Type describes the result after all transforms, not the original resource.
// Build validates syntax only; Parse requires an explicit retrieval policy for
// chains beyond the default raw-certificate/Base64 form.
type RetrievalMethod struct {
	URI, Type  string
	Transforms []reference.Transform
}

// X509Data describes one group of untrusted certificates, CRLs and certificate
// selectors. Build preserves the supplied grouping and original DER bytes. The
// caller must group selectors for the same certificate together and supply the
// intended validation certificate/chain; Build does not match selectors, check
// chain relationships, authenticate CRLs or establish trust. Distinguished names
// are supplied in their XMLDSig/RFC 4514 spelling, not inferred from strings.
type X509Data struct {
	Certificates, CRLs    [][]byte
	IssuerSerials         []IssuerSerial
	SubjectNames          []string
	SubjectKeyIdentifiers [][]byte
	CertificateDigests    []CertificateDigest
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
	// X509Data supplies additional nonempty groups, including selector-only groups.
	// Certificates above, when present, form the first separate group. Each group
	// permits at most 32 entries of each kind; groups, processing work, individual
	// values and aggregate bytes are bounded by the default KeyInfo limits.
	X509Data []X509Data
	// KeyInfoReferences supplies URI references; Build checks syntax, not existence.
	KeyInfoReferences []string
	// RetrievalMethods supplies bounded key-resource descriptions.
	RetrievalMethods []RetrievalMethod
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

	if len(t.Names)+len(t.Keys)+len(t.Certificates)+len(t.X509Data)+len(t.KeyInfoReferences)+len(t.RetrievalMethods) == 0 {
		return nil, ErrInput
	}

	if len(t.Names) > 32 || len(t.Keys) > 32 || len(t.Certificates) > 32 || len(t.KeyInfoReferences) > 32 || len(t.RetrievalMethods) > 32 {
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

	if err := x509TemplateBudget(ctx, &t, &total); err != nil {
		return nil, err
	}

	if err := buildKeys(ctx, t.Keys, root); err != nil {
		return nil, err
	}

	if len(t.Certificates) > 0 {
		if err := buildX509Data(ctx, root, X509Data{Certificates: t.Certificates}); err != nil {
			return nil, err
		}
	}

	for _, group := range t.X509Data {
		if err := buildX509Data(ctx, root, group); err != nil {
			return nil, err
		}
	}

	for _, uri := range t.KeyInfoReferences {
		if len(uri) > 8192 {
			return nil, ErrLimit
		}

		if externalURI(uri) && !validKeyURI(uri) {
			return nil, ErrInput
		}

		r := element(Namespace11, "dsig11", nameKeyInfoReference)
		set(r, "URI", uri)
		add(root, r)
	}

	for _, method := range t.RetrievalMethods {
		if err := buildRetrieval(ctx, root, method, &total); err != nil {
			return nil, err
		}
	}

	doc := tree.FromNodes([]*tree.Node{root}, document.DefaultLimits())

	return tree.Reparse(ctx, doc, document.DefaultLimits())
}

// Preflight all X509Data sources before parsing DER or allocating encoded XML.
// Count parser visits as well as output entries: decoding a selector is work
// even when the same value is repeated in several groups.
func x509TemplateBudget(ctx context.Context, t *Template, total *int) error {
	groups := len(t.X509Data)
	if len(t.Certificates) > 0 {
		groups++
	}

	if groups > 32 {
		return ErrLimit
	}

	visits := 1 + 2*len(t.Names) + len(t.KeyInfoReferences) + len(t.RetrievalMethods)
	for _, key := range t.Keys {
		visits += 3 // item, bare key, binary value

		if key.Format != DERKeyValue {
			switch key.Key.(type) {
			case *rsa.PublicKey:
				visits++
			case *dsa.PublicKey:
				visits += 3
			}
		}
	}

	candidates := len(t.Keys)
	charge := func(size int) error {
		if size > 1<<20 || size > (4<<20)-*total {
			return ErrLimit
		}

		*total += size

		return nil
	}

	check := func(group X509Data) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		counts := []int{len(group.Certificates), len(group.CRLs), len(group.IssuerSerials), len(group.SubjectNames), len(group.SubjectKeyIdentifiers), len(group.CertificateDigests)}
		items := 0

		for _, count := range counts {
			if count > 32 {
				return ErrLimit
			}

			items += count
		}

		if items == 0 {
			return ErrInput
		}

		visits += 1 + 2*items + len(group.IssuerSerials)

		candidates += len(group.Certificates)
		if visits > 256 || candidates > 32 {
			return ErrLimit
		}

		return x509SourceBudget(group, charge)
	}
	if len(t.Certificates) > 0 {
		if err := check(X509Data{Certificates: t.Certificates}); err != nil {
			return err
		}
	}

	for _, group := range t.X509Data {
		if err := check(group); err != nil {
			return err
		}
	}

	return nil
}

func buildRetrieval(ctx context.Context, root *tree.Node, method RetrievalMethod, total *int) error {
	if len(method.URI) > 8192 || len(method.Transforms) > 64 {
		return ErrLimit
	}

	if externalURI(method.URI) && !validKeyURI(method.URI) {
		return ErrInput
	}

	if _, err := retrievalType(method.Type); err != nil {
		return err
	}

	if err := retrievalTemplateBudget(ctx, method, total); err != nil {
		return err
	}

	n := element(Namespace, "ds", "RetrievalMethod")
	set(n, "URI", method.URI)

	if method.Type != "" {
		set(n, "Type", method.Type)
	}

	if len(method.Transforms) != 0 {
		transforms := element(Namespace, "ds", "Transforms")
		for _, transform := range method.Transforms {
			child := element(Namespace, "ds", "Transform")
			set(child, "Algorithm", transform.Algorithm)

			if err := transformxml.AppendParameters(ctx, child, transform); err != nil {
				return retrievalError(err)
			}

			add(transforms, child)
		}

		add(n, transforms)
	}

	add(root, n)

	return nil
}

// Bound all retained parameter sources before importing any stylesheet tree.
func retrievalTemplateBudget(ctx context.Context, method RetrievalMethod, total *int) error {
	charge := func(value string) error {
		if len(value) > (4<<20)-*total {
			return ErrLimit
		}

		*total += len(value)

		return nil
	}
	if err := charge(method.URI); err != nil {
		return err
	}

	if err := charge(method.Type); err != nil {
		return err
	}

	for _, step := range method.Transforms {
		if err := ctx.Err(); err != nil {
			return err
		}

		if len(step.Stylesheet) > (4<<20)-*total {
			return ErrLimit
		}

		*total += len(step.Stylesheet)
		if err := charge(step.Algorithm); err != nil {
			return err
		}

		for _, prefix := range step.InclusivePrefixes {
			if err := charge(prefix); err != nil {
				return err
			}
		}

		for _, expression := range step.XPath {
			if err := retrievalXPathBudget(expression, charge); err != nil {
				return err
			}
		}
	}

	return nil
}

func retrievalXPathBudget(expression reference.XPathExpression, charge func(string) error) error {
	if err := charge(expression.Expression); err != nil {
		return err
	}

	if err := charge(expression.Filter); err != nil {
		return err
	}

	for prefix, uri := range expression.Namespaces {
		if err := charge(prefix); err != nil {
			return err
		}

		if err := charge(uri); err != nil {
			return err
		}
	}

	return nil
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
		der, err := signature.MarshalPublicKey(value.Key)
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
	case *dsa.PublicKey:
		node := element(Namespace, "ds", nameDSAKeyValue)
		for i, value := range []*big.Int{k.P, k.Q, k.G, k.Y} {
			if err := blob(ctx, node, Namespace, "ds", []string{"P", "Q", "G", "Y"}[i], value.Bytes()); err != nil {
				return nil, err
			}
		}

		return node, nil
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
