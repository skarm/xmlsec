package xmldsig

import (
	"fmt"
	"slices"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// Policy bounds signature algorithms, key sizes and processing work. Numeric
// zero values select DefaultPolicy, except MinPSSSaltBytes, which permits zero salt.
// The policy is copied for each operation. Callers must not mutate supplied
// options, keys or signers concurrently with an operation.
type Policy struct {
	// AllowedSignatureMethods lists accepted signature algorithm URIs.
	// Empty selects DefaultPolicy rather than denying all algorithms.
	AllowedSignatureMethods []string
	// AllowedDigestMethods lists accepted reference digest URIs.
	// Empty selects DefaultPolicy rather than denying all algorithms.
	AllowedDigestMethods []string
	// MinRSABits and MaxRSABits bound RSA modulus size; zero selects 2048 and 8192.
	MinRSABits, MaxRSABits int
	// MaxReferences bounds references in each SignedInfo or Manifest; zero selects 16.
	MaxReferences int
	// MaxCanonicalBytes bounds each C14N stream and the total canonical bytes
	// across SignedInfo and all references; zero selects 32 MiB.
	MaxCanonicalBytes int
	// MinPSSSaltBytes bounds generic RSA-PSS salt length; zero permits zero salt.
	MinPSSSaltBytes int
	// MaxPSSSaltBytes bounds generic RSA-PSS salt length; zero selects 1024.
	// The RSA modulus imposes an additional bound.
	MaxPSSSaltBytes int
	// MinHMACKeyBytes and MaxHMACKeyBytes bound shared secrets; zero selects 32 and 4096.
	MinHMACKeyBytes, MaxHMACKeyBytes int
	// MinHMACOutputBits sets the minimum accepted tag length; zero selects 128.
	// Tags must also cover at least half the hash output, in whole bytes.
	MinHMACOutputBits int
	// AllowHMACTruncation permits shorter tags subject to MinHMACOutputBits.
	// False requires a full tag.
	AllowHMACTruncation bool
}

// DefaultPolicy returns the default RSA/ECDSA SHA-2 signature policy.
func DefaultPolicy() Policy {
	return Policy{
		AllowedSignatureMethods: []string{RSASHA256, RSASHA384, RSASHA512, ECDSASHA256, ECDSASHA384, ECDSASHA512},
		AllowedDigestMethods:    []string{SHA256, SHA384, SHA512}, MinRSABits: 2048, MaxRSABits: 8192, MaxReferences: 16, MaxCanonicalBytes: 32 << 20, MaxPSSSaltBytes: 1024, MinHMACKeyBytes: 32, MaxHMACKeyBytes: 4096, MinHMACOutputBits: 128,
	}
}

// ModernPolicy extends DefaultPolicy with fixed-parameter RSA-PSS, Ed25519 and Ed25519ph.
func ModernPolicy() Policy {
	p := DefaultPolicy()
	p.AllowedSignatureMethods = append(p.AllowedSignatureMethods, RSAPSSSHA256, RSAPSSSHA384, RSAPSSSHA512, Ed25519, Ed25519ph)

	return p
}

// ParameterizedPolicy opts into generic RSA-PSS but does not enable HMAC.
func ParameterizedPolicy() Policy {
	p := ModernPolicy()
	p.AllowedSignatureMethods = append(p.AllowedSignatureMethods, RSAPSS)

	return p
}

// HMACPolicy allows only modern HMAC methods. It does not enable truncation or
// public-key methods; the application must explicitly select the correct trust model.
func HMACPolicy() Policy {
	p := DefaultPolicy()
	p.AllowedSignatureMethods = []string{HMACSHA256, HMACSHA384, HMACSHA512}

	return p
}

func normalizePolicy(p Policy) (Policy, error) {
	d := DefaultPolicy()
	if len(p.AllowedSignatureMethods) == 0 {
		p.AllowedSignatureMethods = d.AllowedSignatureMethods
	} else {
		p.AllowedSignatureMethods = append([]string(nil), p.AllowedSignatureMethods...)
	}

	if len(p.AllowedDigestMethods) == 0 {
		p.AllowedDigestMethods = d.AllowedDigestMethods
	} else {
		p.AllowedDigestMethods = append([]string(nil), p.AllowedDigestMethods...)
	}

	if p.MinRSABits == 0 {
		p.MinRSABits = d.MinRSABits
	}

	if p.MaxRSABits == 0 {
		p.MaxRSABits = d.MaxRSABits
	}

	if p.MaxReferences == 0 {
		p.MaxReferences = d.MaxReferences
	}

	if p.MaxCanonicalBytes == 0 {
		p.MaxCanonicalBytes = d.MaxCanonicalBytes
	}

	if p.MinRSABits < 2048 || p.MaxRSABits < p.MinRSABits || p.MaxRSABits > 16384 || p.MaxReferences < 1 || p.MaxReferences > 64 || p.MaxCanonicalBytes < 1 {
		return p, fmt.Errorf("%w: invalid limits", ErrPolicy)
	}

	if p.MaxPSSSaltBytes == 0 {
		p.MaxPSSSaltBytes = d.MaxPSSSaltBytes
	}

	if p.MinHMACKeyBytes == 0 {
		p.MinHMACKeyBytes = d.MinHMACKeyBytes
	}

	if p.MaxHMACKeyBytes == 0 {
		p.MaxHMACKeyBytes = d.MaxHMACKeyBytes
	}

	if p.MinHMACOutputBits == 0 {
		p.MinHMACOutputBits = d.MinHMACOutputBits
	}

	if p.MinPSSSaltBytes < 0 || p.MaxPSSSaltBytes < p.MinPSSSaltBytes || p.MaxPSSSaltBytes > 2048 || p.MinHMACKeyBytes < 32 || p.MaxHMACKeyBytes < p.MinHMACKeyBytes || p.MaxHMACKeyBytes > 1<<20 || p.MinHMACOutputBits < 128 || p.MinHMACOutputBits > 512 || p.MinHMACOutputBits%8 != 0 {
		return p, fmt.Errorf("%w: invalid PSS/HMAC limits", ErrPolicy)
	}

	for _, uri := range p.AllowedSignatureMethods {
		if _, _, e := signatureAlgorithm(uri); e != nil {
			return p, e
		}
	}

	for _, uri := range p.AllowedDigestMethods {
		if _, e := hashForDigest(uri); e != nil {
			return p, e
		}
	}

	return p, nil
}

func permits(allowed []string, value string) bool {
	return slices.Contains(allowed, value)
}

func normalizeID(name document.Name) (document.Name, error) {
	if name == (document.Name{}) {
		name.Local = "ID"
	}

	if !tree.NCName(name.Local) || name.Space == tree.XMLNSNamespace {
		return name, fmt.Errorf("%w: invalid ID attribute QName", ErrPolicy)
	}

	return name, nil
}

func indexIDs(d *document.Document, attribute document.Name) (map[string]*tree.Node, error) {
	ids := make(map[string]*tree.Node)

	var walk func(*tree.Node) error

	walk = func(n *tree.Node) error {
		if n.Kind == tree.ElementNode {
			for _, a := range n.Attrs {
				if a.Name == attribute {
					if !tree.NCName(a.Value) {
						return fmt.Errorf("%w: ID must be an NCName", ErrReference)
					}

					if _, exists := ids[a.Value]; exists {
						return fmt.Errorf("%w: duplicate ID %q", ErrReference, a.Value)
					}

					ids[a.Value] = n
				}
			}
		}

		for _, c := range n.Children {
			if err := walk(c); err != nil {
				return err
			}
		}

		return nil
	}
	if err := walk(tree.Root(d)); err != nil {
		return nil, err
	}

	return ids, nil
}

func getAttr(n *tree.Node, name document.Name) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name == name {
			return a.Value, true
		}
	}

	return "", false
}

func findSignatures(d *document.Document) []*tree.Node {
	var (
		out  []*tree.Node
		walk func(*tree.Node)
	)

	walk = func(n *tree.Node) {
		if n.Kind == tree.ElementNode && n.Name == (document.Name{Space: Namespace, Local: "Signature"}) {
			out = append(out, n)
		}

		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root(d))

	return out
}
