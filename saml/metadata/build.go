package metadata

import (
	"context"
	"crypto"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// KeyDescriptor advertises a DER certificate for signing, encryption or both uses.
type KeyDescriptor struct {
	// Use is signing, encryption or empty for both uses.
	Use string
	// CertificateDER is the DER certificate advertised for this key. It does not establish
	// trust.
	CertificateDER []byte
}

// RoleDescriptor supplies keys, endpoints and signature requirements for a supported
// SAML role.
type RoleDescriptor struct {
	// Keys lists certificates advertised for this role and their intended uses.
	Keys []KeyDescriptor
	// Endpoints maps metadata element local names, such as [AssertionConsumerService],
	// to their endpoint declarations.
	Endpoints map[string][]Endpoint
	// NameIDFormats lists supported subject identifier format URIs.
	NameIDFormats []string
	// ValidUntil, when nonzero, narrows the entity's validity period.
	ValidUntil time.Time
	// AuthnRequestsSigned declares that this SP signs its authentication requests.
	AuthnRequestsSigned bool
	// WantAuthnRequestsSigned declares that this IdP requires signed authentication
	// requests.
	WantAuthnRequestsSigned bool
	// WantAssertionsSigned declares that this SP requires signed assertions.
	WantAssertionsSigned bool
}

// EntityDescriptor supplies an entity identifier, expiration and optional SP and IdP
// roles.
type EntityDescriptor struct {
	// ID is the entity descriptor XML ID. Empty generates an unpredictable ID.
	ID string
	// EntityID is the required SAML entity identifier URI.
	EntityID string
	// ValidUntil is the required entity metadata expiration time.
	ValidUntil time.Time
	// CacheDuration optionally limits metadata caching. Zero omits the attribute.
	CacheDuration time.Duration
	// SP supplies the service provider role. Nil omits that role.
	SP *RoleDescriptor
	// IDP supplies the identity provider role. Nil omits that role.
	IDP *RoleDescriptor
}

// Build builds a supported metadata document with explicit validity. The returned document
// is unsigned.
func Build(ctx context.Context, s EntityDescriptor, at time.Time, o Options) (*document.Document, error) {
	var err error

	o, err = normalize(o)
	if err != nil {
		return nil, err
	}

	if returned1, matched := buildIsZero(ctx, &at, &s); matched {
		return nil, returned1
	}

	id := s.ID
	if id == "" {
		var e error

		id, e = xmlutil.NewID()
		if e != nil {
			return nil, e
		}
	}

	if !xmlutil.ID(id) {
		return nil, ErrMetadata
	}

	root := md("EntityDescriptor")
	root.NS = []tree.Namespace{{Prefix: "md", URI: Namespace}, {Prefix: "ds", URI: xmlutil.DS}}
	xmlutil.Set(root, "ID", id)
	xmlutil.Set(root, "entityID", s.EntityID)
	xmlutil.Set(root, nameValidUntil, xmlutil.Time(s.ValidUntil))

	if returned1Value, matchedBranch := buildCacheDuration(&s, root); matchedBranch {
		return nil, returned1Value
	}

	if returned1ValueValue, matchedBranchBranch := buildEntries(ctx, &s, root, o.MaxKeysPerRole); matchedBranchBranch {
		return nil, returned1ValueValue
	}

	d, e := xmlutil.Document(ctx, root)
	if e != nil {
		return nil, e
	}

	if _, e := d.WriteXML(ctx, io.Discard, o.MaxBytes); e != nil {
		if errors.Is(e, document.ErrLimit) {
			return nil, errors.Join(ErrMetadata, e)
		}

		return nil, e
	}

	if _, e := parse(ctx, d, at, o); e != nil {
		return nil, e
	}

	return d, nil
}

func md(local string) *tree.Node { return xmlutil.Node("md", Namespace, local) }

func buildOrder(order []string, r *struct {
	kind RoleType
	spec *RoleDescriptor
}, n *tree.Node, used map[string]struct{},
) {
	for _, kind := range order {
		if kind == nameNameIDFormat {
			for _, f := range r.spec.NameIDFormats {
				nf := md(kind)
				xmlutil.Text(nf, f)
				xmlutil.Add(n, nf)
			}

			continue
		}

		used[kind] = struct{}{}
		for _, ep := range r.spec.Endpoints[kind] {
			n2 := md(kind)
			xmlutil.Set(n2, "Binding", ep.Binding)
			xmlutil.Set(n2, "Location", ep.Location)

			if ep.ResponseLocation != "" {
				xmlutil.Set(n2, "ResponseLocation", ep.ResponseLocation)
			}

			if kind == AssertionConsumerService || kind == ArtifactResolutionService {
				xmlutil.Set(n2, "index", strconv.Itoa(int(ep.Index)))

				if ep.DefaultSet || ep.Default {
					xmlutil.Set(n2, "isDefault", strconv.FormatBool(ep.Default))
				}
			}

			xmlutil.Add(n, n2)
		}
	}
}

func buildIsZero(ctx context.Context, at *time.Time, s *EntityDescriptor) (returned1 error, matched bool) {
	if ctx == nil || at.IsZero() || s.ValidUntil.IsZero() || !s.ValidUntil.After(*at) || s.SP == nil && s.IDP == nil || !xmlutil.URI(s.EntityID) {
		return ErrMetadata, true
	}

	return
}

func buildCacheDuration(s *EntityDescriptor, root *tree.Node) (returned1Value error, matchedBranch bool) {
	if s.CacheDuration != 0 {
		if s.CacheDuration <= 0 || s.CacheDuration > 365*24*time.Hour {
			return ErrMetadata, true
		}

		secs := s.CacheDuration / time.Second
		frac := s.CacheDuration % time.Second

		value := strconv.FormatInt(int64(secs), 10)
		if frac != 0 {
			value += "." + strings.TrimRight(strconv.FormatInt(int64(frac)+1e9, 10)[1:], "0")
		}

		xmlutil.Set(root, nameCacheDuration, "PT"+value+"S")
	}

	return
}

func buildEntries(ctx context.Context, s *EntityDescriptor, root *tree.Node, maxKeys int) (returned1ValueValue error, matchedBranchBranch bool) {
	for _, r := range []struct {
		kind RoleType
		spec *RoleDescriptor
	}{{IdentityProvider, s.IDP}, {ServiceProvider, s.SP}} {
		if r.spec == nil {
			continue
		}

		if len(r.spec.Keys) > maxKeys {
			return ErrMetadata, true
		}

		n := md(string(r.kind))
		xmlutil.Set(n, "protocolSupportEnumeration", Protocol)

		if !r.spec.ValidUntil.IsZero() {
			xmlutil.Set(n, nameValidUntil, xmlutil.Time(r.spec.ValidUntil))
		}

		if r.kind == IdentityProvider {
			xmlutil.Set(n, "WantAuthnRequestsSigned", strconv.FormatBool(r.spec.WantAuthnRequestsSigned))
		} else {
			xmlutil.Set(n, "AuthnRequestsSigned", strconv.FormatBool(r.spec.AuthnRequestsSigned))
			xmlutil.Set(n, "WantAssertionsSigned", strconv.FormatBool(r.spec.WantAssertionsSigned))
		}

		for _, k := range r.spec.Keys {
			if len(k.CertificateDER) > 32<<10 {
				return ErrMetadata, true
			}

			encoded, err := tree.EncodeBase64(ctx, k.CertificateDER)
			if err != nil {
				return err, true
			}

			kd := md("KeyDescriptor")
			if k.Use != "" {
				xmlutil.Set(kd, "use", k.Use)
			}

			ki := xmlutil.Node("ds", xmlutil.DS, lexicon.DSigElementKeyInfo)
			xd := xmlutil.Node("ds", xmlutil.DS, lexicon.DSigElementX509Data)
			xc := xmlutil.Node("ds", xmlutil.DS, lexicon.DSigElementX509Certificate)
			xmlutil.Text(xc, encoded)
			xmlutil.Add(xd, xc)
			xmlutil.Add(ki, xd)
			xmlutil.Add(kd, ki)
			xmlutil.Add(n, kd)
		}

		order := []string{ArtifactResolutionService, SingleLogoutService, ManageNameIDService, nameNameIDFormat}
		if r.kind == IdentityProvider {
			order = append(order, SingleSignOnService, NameIDMappingService)
		} else {
			order = append(order, AssertionConsumerService)
		}

		used := map[string]struct{}{}

		buildOrder(order, &r, n, used)

		for kind := range r.spec.Endpoints {
			if _, exists := used[kind]; !exists {
				return ErrMetadata, true
			}
		}

		xmlutil.Add(root, n)
	}

	return returned1ValueValue, matchedBranchBranch
}

// Sign creates a root signature before the first metadata child. Unlike
// Verify, signing an aggregate that already contains signatures is not supported.
func Sign(ctx context.Context, d *document.Document, key crypto.Signer, certificateDER []byte, method string, at time.Time, o Options) (*document.Document, error) {
	if d == nil || len(xmldsig.Signatures(d)) != 0 {
		return nil, ErrMetadata
	}

	signed, e := xmlsig.Sign(ctx, d, d.Root(), xmlsig.SigningKey{Key: key, CertificateDER: certificateDER, Method: method, Policy: o.Policy}, false)
	if e != nil {
		return nil, e
	}

	v, e := NewVerifier(Config{TrustedKeys: []crypto.PublicKey{key.Public()}, Options: o})
	if e != nil {
		return nil, e
	}

	if _, e := signed.WriteXML(ctx, io.Discard, v.o.MaxBytes); e != nil {
		if errors.Is(e, document.ErrLimit) {
			return nil, errors.Join(ErrMetadata, e)
		}

		return nil, e
	}

	if _, e := v.verifyDocument(ctx, signed, at); e != nil {
		return nil, e
	}

	return signed, nil
}
