package keyinfo

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/internal/x509crl"
)

const (
	nameX509Digest       = "X509Digest"
	nameX509IssuerName   = "X509IssuerName"
	nameX509IssuerSerial = "X509IssuerSerial"
	nameX509SerialNumber = "X509SerialNumber"
	nameX509SubjectName  = "X509SubjectName"
)

func (p *parser) certificate(s *scope, n *tree.Node, der []byte) error {
	c, err := x509cert.ParseWithMaxBytes(der, p.limits.MaxBlobBytes)
	if err != nil {
		return fmt.Errorf("%w: X509Certificate: %w", ErrInput, err)
	}

	return p.addCandidate(s, n, c.PublicKey, der)
}

func (p *parser) x509Data(s *scope, n *tree.Node) error {
	children, err := structure(n, Namespace, nameX509Data)
	if err != nil {
		return err
	}

	if len(children) == 0 {
		return ErrInput
	}

	group := X509Group{source: tree.Wrap(s.doc, n)}

	for _, child := range children {
		if err := p.tick(); err != nil {
			return err
		}

		if err := p.x509DataItem(s, child, &group); err != nil {
			return err
		}
	}

	p.result.groups = append(p.result.groups, group)

	return nil
}

// x509DataItem validates one selector before adding it to its containing group.
// Certificates also enter the candidate list immediately, in document order.
func (p *parser) x509DataItem(s *scope, n *tree.Node, group *X509Group) error {
	switch n.Name {
	case document.Name{Space: Namespace, Local: nameX509Certificate}:
		der, err := p.binary(n)
		if err != nil {
			return err
		}

		if err := p.certificate(s, n, der); err != nil {
			return err
		}

		group.certs = append(group.certs, der)
	case document.Name{Space: Namespace, Local: nameX509CRL}:
		der, err := p.binary(n)
		if err != nil {
			return err
		}

		if _, err := x509crl.ParseEvidence(der, p.limits.MaxBlobBytes); err != nil {
			return fmt.Errorf("%w: X509CRL: %w", ErrInput, err)
		}

		group.crls = append(group.crls, der)
	case document.Name{Space: Namespace, Local: nameX509SubjectName}:
		name, err := p.stringValue(n)
		if err != nil {
			return err
		}

		if strings.TrimSpace(name) == "" {
			return ErrInput
		}

		group.subjects = append(group.subjects, name)
	case document.Name{Space: Namespace, Local: nameX509SKI}:
		keyID, err := p.binary(n)
		if err != nil {
			return err
		}

		group.skis = append(group.skis, keyID)
	case document.Name{Space: Namespace, Local: nameX509IssuerSerial}:
		issuer, err := p.x509IssuerSerial(n)
		if err != nil {
			return err
		}

		group.issuers = append(group.issuers, issuer)
	case document.Name{Space: Namespace11, Local: nameX509Digest}:
		digest, err := p.x509Digest(n)
		if err != nil {
			return err
		}

		group.digests = append(group.digests, digest)
	default:
		return fmt.Errorf("%w: X509Data child", ErrUnsupported)
	}

	return nil
}

func (p *parser) x509IssuerSerial(n *tree.Node) (IssuerSerial, error) {
	children, err := structure(n, Namespace, nameX509IssuerSerial)
	if err != nil {
		return IssuerSerial{}, err
	}

	if len(children) != 2 || !is(children[0], Namespace, nameX509IssuerName) || !is(children[1], Namespace, nameX509SerialNumber) {
		return IssuerSerial{}, ErrInput
	}

	issuer, err := p.stringValue(children[0])
	if err != nil {
		return IssuerSerial{}, err
	}

	serial, err := p.stringValue(children[1])
	if err != nil {
		return IssuerSerial{}, err
	}

	return normalizeIssuerSerial(issuer, serial)
}

func (p *parser) x509Digest(n *tree.Node) (CertificateDigest, error) {
	algorithm, ok := attr(n, lexicon.SecurityAttrAlgorithm)
	if !ok {
		return CertificateDigest{}, ErrInput
	}

	size := x509DigestSize(algorithm)
	if size == 0 {
		return CertificateDigest{}, fmt.Errorf("%w: certificate digest algorithm", ErrUnsupported)
	}

	value, err := p.binary(n, lexicon.SecurityAttrAlgorithm)
	if err != nil {
		return CertificateDigest{}, err
	}

	if len(value) != size {
		return CertificateDigest{}, ErrInput
	}

	return CertificateDigest{algorithm, value}, nil
}

func (p *parser) tick() error {
	if err := p.ctx.Err(); err != nil {
		return err
	}

	p.elements++
	if p.elements > p.limits.MaxElements {
		return fmt.Errorf("%w: processing elements", ErrLimit)
	}

	return nil
}

func normalizeIssuerSerial(issuer, serial string) (IssuerSerial, error) {
	serial = strings.Trim(serial, lexicon.XMLWhitespace)
	serial = strings.TrimPrefix(serial, "+")

	if serial == "" || strings.TrimSpace(issuer) == "" {
		return IssuerSerial{}, ErrInput
	}

	// Normalize decimal spelling in linear time, without parsing an
	// attacker-controlled decimal string into a big integer.
	for i := 0; i < len(serial); i++ {
		if serial[i] < '0' || serial[i] > '9' {
			return IssuerSerial{}, ErrInput
		}
	}

	serial = strings.TrimLeft(serial, "0")
	if serial == "" {
		serial = "0"
	}

	return IssuerSerial{issuer, serial}, nil
}

func x509SourceBudget(group X509Data, charge func(int) error) error {
	for _, values := range [][][]byte{group.Certificates, group.CRLs, group.SubjectKeyIdentifiers} {
		for _, value := range values {
			if err := charge(len(value)); err != nil {
				return err
			}
		}
	}

	for _, issuer := range group.IssuerSerials {
		if err := charge(len(issuer.Issuer)); err != nil {
			return err
		}

		if err := charge(len(issuer.Serial)); err != nil {
			return err
		}
	}

	for _, subject := range group.SubjectNames {
		if err := charge(len(subject)); err != nil {
			return err
		}
	}

	for _, digest := range group.CertificateDigests {
		if err := charge(len(digest.Algorithm)); err != nil {
			return err
		}

		if err := charge(len(digest.Value)); err != nil {
			return err
		}
	}

	return nil
}

func buildX509Data(ctx context.Context, root *tree.Node, group X509Data) error {
	n := element(Namespace, lexicon.PrefixDSig, nameX509Data)

	for _, issuer := range group.IssuerSerials {
		value, err := normalizeIssuerSerial(issuer.Issuer, issuer.Serial)
		if err != nil {
			return err
		}

		pair := element(Namespace, lexicon.PrefixDSig, nameX509IssuerSerial)
		addString(pair, nameX509IssuerName, value.Issuer)
		addString(pair, nameX509SerialNumber, value.Serial)
		add(n, pair)
	}

	for _, subject := range group.SubjectNames {
		if strings.TrimSpace(subject) == "" {
			return ErrInput
		}

		addString(n, nameX509SubjectName, subject)
	}

	if err := buildX509Blobs(ctx, n, group); err != nil {
		return err
	}

	for _, digest := range group.CertificateDigests {
		size := x509DigestSize(digest.Algorithm)
		if size == 0 {
			return fmt.Errorf("%w: certificate digest algorithm", ErrUnsupported)
		}

		if len(digest.Value) != size {
			return ErrInput
		}

		child := element(Namespace11, lexicon.PrefixDSig11, nameX509Digest)
		set(child, lexicon.SecurityAttrAlgorithm, digest.Algorithm)

		encoded, err := tree.EncodeBase64(ctx, digest.Value)
		if err != nil {
			return err
		}

		addText(child, encoded)
		add(n, child)
	}

	add(root, n)

	return ctx.Err()
}

func addString(parent *tree.Node, local, value string) {
	n := element(Namespace, lexicon.PrefixDSig, local)
	addText(n, value)
	add(parent, n)
}

func buildX509Blobs(ctx context.Context, node *tree.Node, group X509Data) error {
	for _, field := range []struct {
		name   string
		values [][]byte
	}{
		{nameX509Certificate, group.Certificates},
		{nameX509CRL, group.CRLs},
		{nameX509SKI, group.SubjectKeyIdentifiers},
	} {
		for _, value := range field.values {
			if err := ctx.Err(); err != nil {
				return err
			}

			switch field.name {
			case nameX509Certificate:
				if _, err := x509cert.ParseWithMaxBytes(value, len(value)); err != nil {
					return fmt.Errorf("%w: certificate: %w", ErrInput, err)
				}
			case nameX509CRL:
				if _, err := x509crl.ParseEvidence(value, len(value)); err != nil {
					return fmt.Errorf("%w: CRL: %w", ErrInput, err)
				}
			case nameX509SKI:
				if len(value) == 0 {
					return ErrInput
				}
			}

			if err := blob(ctx, node, Namespace, lexicon.PrefixDSig, field.name, value); err != nil {
				return err
			}
		}
	}

	return nil
}

func x509DigestSize(algorithm string) int {
	const legacySHA1DigestBytes = 20

	switch algorithm {
	case lexicon.DigestSHA1:
		return legacySHA1DigestBytes
	case lexicon.DigestSHA256:
		return sha256.Size
	case lexicon.DigestSHA384:
		return sha512.Size384
	case lexicon.DigestSHA512:
		return sha512.Size
	default:
		return 0
	}
}
