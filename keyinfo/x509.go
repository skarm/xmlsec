package keyinfo

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

func (p *parser) certificate(s *scope, n *tree.Node, der []byte) error {
	c, err := x509.ParseCertificate(der)
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
	case document.Name{Space: Namespace, Local: "X509Certificate"}:
		der, err := p.binary(n)
		if err != nil {
			return err
		}

		if err := p.certificate(s, n, der); err != nil {
			return err
		}

		group.certs = append(group.certs, der)
	case document.Name{Space: Namespace, Local: "X509CRL"}:
		der, err := p.binary(n)
		if err != nil {
			return err
		}

		if _, err := x509.ParseRevocationList(der); err != nil {
			return fmt.Errorf("%w: X509CRL: %w", ErrInput, err)
		}

		group.crls = append(group.crls, der)
	case document.Name{Space: Namespace, Local: "X509SubjectName"}:
		name, err := p.stringValue(n)
		if err != nil {
			return err
		}

		if strings.TrimSpace(name) == "" {
			return ErrInput
		}

		group.subjects = append(group.subjects, name)
	case document.Name{Space: Namespace, Local: "X509SKI"}:
		keyID, err := p.binary(n)
		if err != nil {
			return err
		}

		group.skis = append(group.skis, keyID)
	case document.Name{Space: Namespace, Local: "X509IssuerSerial"}:
		issuer, err := p.x509IssuerSerial(n)
		if err != nil {
			return err
		}

		group.issuers = append(group.issuers, issuer)
	case document.Name{Space: Namespace11, Local: "X509Digest"}:
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
	children, err := structure(n, Namespace, "X509IssuerSerial")
	if err != nil {
		return IssuerSerial{}, err
	}

	if len(children) != 2 || !is(children[0], Namespace, "X509IssuerName") || !is(children[1], Namespace, "X509SerialNumber") {
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

	serial = strings.Trim(serial, " \t\r\n")
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

func (p *parser) x509Digest(n *tree.Node) (CertificateDigest, error) {
	algorithm, ok := attr(n, "Algorithm")
	if !ok {
		return CertificateDigest{}, ErrInput
	}

	size := x509DigestSize(algorithm)
	if size == 0 {
		return CertificateDigest{}, fmt.Errorf("%w: certificate digest algorithm", ErrUnsupported)
	}

	value, err := p.binary(n, "Algorithm")
	if err != nil {
		return CertificateDigest{}, err
	}

	if len(value) != size {
		return CertificateDigest{}, ErrInput
	}

	return CertificateDigest{algorithm, value}, nil
}

func x509DigestSize(algorithm string) int {
	switch algorithm {
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		return 20
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return 32
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		return 48
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		return 64
	default:
		return 0
	}
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
