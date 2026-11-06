package xmldsig

import (
	"fmt"
	"slices"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

const (
	defaultMaxCanonicalBytes = 32 << 20
	defaultMaxHMACKeyBytes   = 4096
	defaultMaxPSSSaltBytes   = 1024
	defaultMaxRSAKeyBits     = 8192
	defaultMaxReferences     = 16
	maximumHMACOutputBits    = 512
	maximumRSAKeyBits        = 16384
	maximumReferences        = 64
	// Minimum byte length accepted for an explicitly supplied HMAC key.
	minimumHMACKeyBytes   = 32
	minimumHMACOutputBits = 128
	minimumRSAKeyBits     = 2048
)

// Policy restricts signature algorithms, key sizes and processing work.
// Zero numeric fields select DefaultPolicy, except MinPSSSaltBytes: zero permits
// zero-length salt. Each operation copies the policy. Callers must keep supplied
// options, keys and signers unchanged until the operation returns.
type Policy struct {
	// AllowedSignatureMethods lists accepted signature algorithm URIs.
	// Empty selects DefaultPolicy rather than denying all algorithms.
	AllowedSignatureMethods []string
	// AllowedDigestMethods lists accepted reference digest URIs.
	// Empty selects DefaultPolicy rather than denying all algorithms.
	AllowedDigestMethods []string
	// MinRSABits sets the minimum RSA modulus size. Zero selects 2048 bits.
	MinRSABits int
	// MaxRSABits bounds RSA modulus size. Zero selects 8192 bits.
	MaxRSABits int
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
	// MinHMACKeyBytes sets the minimum shared secret size. Zero selects 32 bytes.
	MinHMACKeyBytes int
	// MaxHMACKeyBytes bounds shared secret size. Zero selects 4096 bytes.
	MaxHMACKeyBytes int
	// MinHMACOutputBits sets the minimum accepted tag length; zero selects 128.
	// Tags must also cover at least half the hash output, in whole bytes.
	MinHMACOutputBits int
	// AllowLegacySigning permits RSA-SHA1 generation only when the signature
	// allowlist also permits it. SHA-1 reference digests need a separate digest
	// allowlist entry. Verification permission alone never enables legacy signing.
	// SHA-1 remains disabled in FIPS mode.
	AllowLegacySigning bool
	// AllowHMACTruncation permits shorter tags subject to MinHMACOutputBits.
	// False requires a full tag.
	AllowHMACTruncation bool
}

// DefaultPolicy returns the default RSA/ECDSA SHA-2 signature policy.
func DefaultPolicy() Policy {
	return Policy{
		AllowedSignatureMethods: []string{RSASHA256, RSASHA384, RSASHA512, ECDSASHA256, ECDSASHA384, ECDSASHA512},
		AllowedDigestMethods:    []string{SHA256, SHA384, SHA512}, MinRSABits: minimumRSAKeyBits, MaxRSABits: defaultMaxRSAKeyBits, MaxReferences: defaultMaxReferences, MaxCanonicalBytes: defaultMaxCanonicalBytes, MaxPSSSaltBytes: defaultMaxPSSSaltBytes, MinHMACKeyBytes: minimumHMACKeyBytes, MaxHMACKeyBytes: defaultMaxHMACKeyBytes, MinHMACOutputBits: minimumHMACOutputBits,
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

// LegacyVerificationPolicy opts into SHA-1 reference digests and RSA-SHA1/DSA-SHA1
// verification. DSA is limited to the 1024/160 profile. Legacy signature
// generation remains disabled unless AllowLegacySigning is separately enabled;
// modern defaults and RSA size limits are retained.
// This policy does not enable HMAC. Legacy policies are disabled in FIPS mode.
func LegacyVerificationPolicy() Policy {
	p := ModernPolicy()
	p.AllowedSignatureMethods = append(p.AllowedSignatureMethods, RSASHA1, DSASHA1)
	p.AllowedDigestMethods = append(p.AllowedDigestMethods, SHA1)

	return p
}

// LegacyHMACPolicy explicitly permits HMAC-SHA1 and SHA-1 reference digests in
// the shared-secret APIs, alongside HMAC SHA-2. It retains key/tag bounds and
// does not enable truncation or public-key methods. It is disabled in FIPS mode.
func LegacyHMACPolicy() Policy {
	p := HMACPolicy()
	p.AllowedSignatureMethods = append(p.AllowedSignatureMethods, HMACSHA1)
	p.AllowedDigestMethods = append(p.AllowedDigestMethods, SHA1)

	return p
}

// IntersectPolicies returns a policy that enforces both input policies. Each
// input is validated and its zero fields select the usual Policy defaults.
// The result owns its algorithm lists and retains the order of the first input.
// Neither input is modified.
//
// Incompatible bounds or disjoint signature or digest allowlists return an
// error and a zero policy. A disjoint digest allowlist is rejected even for
// message-only uses: Policy cannot express an empty allowlist without restoring
// the default algorithms. Callers must not use the returned policy on error.
func IntersectPolicies(first, second Policy) (Policy, error) {
	a, err := normalizePolicy(first)
	if err != nil {
		return Policy{}, fmt.Errorf("first policy: %w", err)
	}

	b, err := normalizePolicy(second)
	if err != nil {
		return Policy{}, fmt.Errorf("second policy: %w", err)
	}

	p := Policy{
		AllowLegacySigning:      a.AllowLegacySigning && b.AllowLegacySigning,
		AllowedSignatureMethods: intersectPolicyMethods(a.AllowedSignatureMethods, b.AllowedSignatureMethods),
		AllowedDigestMethods:    intersectPolicyMethods(a.AllowedDigestMethods, b.AllowedDigestMethods),
		MinRSABits:              max(a.MinRSABits, b.MinRSABits),
		MaxRSABits:              min(a.MaxRSABits, b.MaxRSABits),
		MaxReferences:           min(a.MaxReferences, b.MaxReferences),
		MaxCanonicalBytes:       min(a.MaxCanonicalBytes, b.MaxCanonicalBytes),
		MinPSSSaltBytes:         max(a.MinPSSSaltBytes, b.MinPSSSaltBytes),
		MaxPSSSaltBytes:         min(a.MaxPSSSaltBytes, b.MaxPSSSaltBytes),
		MinHMACKeyBytes:         max(a.MinHMACKeyBytes, b.MinHMACKeyBytes),
		MaxHMACKeyBytes:         min(a.MaxHMACKeyBytes, b.MaxHMACKeyBytes),
		MinHMACOutputBits:       max(a.MinHMACOutputBits, b.MinHMACOutputBits),
		AllowHMACTruncation:     a.AllowHMACTruncation && b.AllowHMACTruncation,
	}
	if len(p.AllowedSignatureMethods) == 0 || len(p.AllowedDigestMethods) == 0 {
		return Policy{}, fmt.Errorf("%w: disjoint algorithm allowlists", ErrPolicy)
	}

	p, err = normalizePolicy(p)
	if err != nil {
		return Policy{}, fmt.Errorf("intersected policy: %w", err)
	}

	return p, nil
}

func intersectPolicyMethods(first, second []string) []string {
	allowed := make(map[string]struct{}, len(second))
	for _, method := range second {
		allowed[method] = struct{}{}
	}

	result := make([]string, 0, min(len(first), len(second)))
	for _, method := range first {
		if _, ok := allowed[method]; ok {
			result = append(result, method)
		}
	}

	return result
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

	if p.MinRSABits < minimumRSAKeyBits || p.MaxRSABits < p.MinRSABits || p.MaxRSABits > maximumRSAKeyBits || p.MaxReferences < 1 || p.MaxReferences > maximumReferences || p.MaxCanonicalBytes < 1 {
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

	if p.MinPSSSaltBytes < 0 || p.MaxPSSSaltBytes < p.MinPSSSaltBytes || p.MaxPSSSaltBytes > maximumPSSSaltBytes || p.MinHMACKeyBytes < minimumHMACKeyBytes || p.MaxHMACKeyBytes < p.MinHMACKeyBytes || p.MaxHMACKeyBytes > maximumHMACKeyBytes || p.MinHMACOutputBits < minimumHMACOutputBits || p.MinHMACOutputBits > maximumHMACOutputBits || p.MinHMACOutputBits%signatureOctetBits != 0 {
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
		name.Local = defaultIDAttribute
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
		if n.Kind == tree.ElementNode && n.Name == (document.Name{Space: Namespace, Local: lexicon.DSigElementSignature}) {
			out = append(out, n)
		}

		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root(d))

	return out
}
