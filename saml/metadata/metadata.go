package metadata

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/x509cert"
	"github.com/skarm/xmlsec/saml/internal/profile"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmldsig"
)

// Namespace is the SAML 2.0 metadata namespace URI.
const Namespace = xmlutil.Metadata

// Protocol is the SAML 2.0 protocol identifier used in metadata.
const Protocol = xmlutil.Protocol

// HTTPPost is the SAML HTTP-POST binding URI.
const HTTPPost = lexicon.SAMLBindingHTTPPost

// HTTPRedirect is the SAML HTTP-Redirect binding URI.
const HTTPRedirect = lexicon.SAMLBindingHTTPRedirect

// HTTPArtifact is the SAML HTTP-Artifact binding URI; artifact processing is unsupported.
const HTTPArtifact = lexicon.SAMLBindingHTTPArtifact

// SOAP is the SAML SOAP binding URI; SOAP processing is unsupported.
const SOAP = lexicon.SAMLBindingSOAP

const (
	// AssertionConsumerService selects assertion consumer endpoints in Role.Endpoints.
	AssertionConsumerService = lexicon.SAMLAssertionConsumerService
	// SingleSignOnService selects IdP sign-on endpoints in Role.Endpoints.
	SingleSignOnService = lexicon.SAMLSingleSignOnService
	// SingleLogoutService selects logout declarations; logout processing is unsupported.
	SingleLogoutService = lexicon.SAMLSingleLogoutService
	// ArtifactResolutionService selects artifact declarations; artifact processing is unsupported.
	ArtifactResolutionService = lexicon.SAMLArtifactResolutionService
	// ManageNameIDService selects name identifier management declarations, without enabling processing.
	ManageNameIDService = lexicon.SAMLManageNameIDService
	// NameIDMappingService selects name identifier mapping declarations, without enabling processing.
	NameIDMappingService = lexicon.SAMLNameIDMappingService
)

// ErrMetadata reports SAML metadata rejected.
var ErrMetadata = errors.New("SAML metadata rejected")

// ErrExpired reports SAML metadata expired or requires refresh.
var ErrExpired = errors.New("SAML metadata expired or requires refresh")

// RoleType identifies an SP or IdP metadata role.
type RoleType string

const (
	// ServiceProvider identifies an SPSSODescriptor metadata role.
	ServiceProvider RoleType = "SPSSODescriptor"
	// IdentityProvider identifies an IDPSSODescriptor metadata role.
	IdentityProvider RoleType = "IDPSSODescriptor"
)

// Endpoint identifies a binding and its service URL, with optional response URL and
// indexed service selection.
type Endpoint struct {
	// Binding is the SAML binding URI supported by this endpoint.
	Binding string
	// Location is the endpoint URL.
	Location string
	// ResponseLocation is the optional URL for responses associated with this endpoint.
	ResponseLocation string
	// Index identifies an indexed endpoint and applies only when Indexed is true.
	Index uint16
	// Indexed distinguishes an indexed endpoint, including index zero, from an unindexed one.
	Indexed bool
	// Default is the isDefault value when DefaultSet is true.
	Default bool
	// DefaultSet distinguishes an explicit false isDefault value from an absent attribute.
	DefaultSet bool
}

// SelectACS selects from caller-authorized endpoints, preserving metadata order.
// A nil index uses IndexedEndpointType's isDefault rules: first true, then first
// unspecified, then first endpoint. Selection alone does not establish trust.
func SelectACS(endpoints []Endpoint, binding string, index *uint16) (Endpoint, error) {
	var first, unspecified Endpoint

	haveFirst, haveUnspecified := false, false

	for _, endpoint := range endpoints {
		if endpoint.Binding != binding || index != nil && endpoint.Index != *index {
			continue
		}

		if index != nil || endpoint.Default {
			return endpoint, nil
		}

		if !haveFirst {
			first, haveFirst = endpoint, true
		}

		if !endpoint.DefaultSet && !haveUnspecified {
			unspecified, haveUnspecified = endpoint, true
		}
	}

	if haveUnspecified {
		return unspecified, nil
	}

	if haveFirst {
		return first, nil
	}

	return Endpoint{}, ErrMetadata
}

// Role retains immutable role metadata and its effective expiration time.
type Role struct {
	kind                 RoleType
	keys                 []key
	endpoints            map[string][]Endpoint
	formats              []string
	expires              time.Time
	authnSigned          bool
	wantAuthnSigned      bool
	wantAssertionsSigned bool
}

// Type returns the metadata role type.
func (r *Role) Type() RoleType {
	if r == nil {
		return ""
	}

	return r.kind
}

// ExpiresAt returns the exclusive expiration boundary.
func (r *Role) ExpiresAt() time.Time {
	if r == nil {
		return time.Time{}
	}

	return r.expires
}

// AuthnRequestsSigned returns whether metadata declares that the SP signs authentication
// requests.
func (r *Role) AuthnRequestsSigned() bool { return r != nil && r.authnSigned }

// WantAuthnRequestsSigned returns whether metadata requires signed authentication
// requests.
func (r *Role) WantAuthnRequestsSigned() bool { return r != nil && r.wantAuthnSigned }

// WantAssertionsSigned returns whether metadata requires signed assertions.
func (r *Role) WantAssertionsSigned() bool { return r != nil && r.wantAssertionsSigned }

// NameIDFormats returns an owned copy of the supported NameID format URIs.
func (r *Role) NameIDFormats() []string {
	if r == nil {
		return nil
	}

	return append([]string(nil), r.formats...)
}

// Endpoints returns an owned copy of endpoints for the requested service kind.
func (r *Role) Endpoints(kind string) []Endpoint {
	if r == nil {
		return nil
	}

	return append([]Endpoint(nil), r.endpoints[kind]...)
}

// Certificates returns owned certificate DER values for the requested use, including
// descriptors with unspecified use.
func (r *Role) Certificates(use string) [][]byte {
	if r == nil {
		return nil
	}

	var out [][]byte

	for _, k := range r.keys {
		if k.use == "" || k.use == use {
			out = append(out, bytes.Clone(k.der))
		}
	}

	return out
}

// SigningKeys returns owned, deduplicated signing keys from trusted metadata. It does not
// independently validate certificate lifetimes.
func (r *Role) SigningKeys() []crypto.PublicKey {
	if r == nil {
		return nil
	}

	var out []crypto.PublicKey

	seen := map[string]struct{}{}
	for _, k := range r.keys {
		if _, exists := seen[string(k.spki)]; (k.use == "" || k.use == "signing") && !exists {
			pub, e := x509.ParsePKIXPublicKey(k.spki)
			if e == nil {
				out = append(out, pub)
				seen[string(k.spki)] = struct{}{}
			}
		}
	}

	return out
}

// ACS selects a declared endpoint only. A supplied URL from a request never
// becomes authorized merely by matching a host or URL prefix.
func (r *Role) ACS(binding string, index *uint16) (Endpoint, error) {
	if r == nil || r.kind != ServiceProvider {
		return Endpoint{}, ErrMetadata
	}

	return SelectACS(r.endpoints[AssertionConsumerService], binding, index)
}

// Entity retains immutable metadata for one entity, its supported roles and effective
// expiration.
type Entity struct {
	id      string
	expires time.Time
	roles   map[RoleType]*Role
}

// ID returns the metadata entity identifier.
func (e *Entity) ID() string {
	if e == nil {
		return ""
	}

	return e.id
}

// ExpiresAt returns the exclusive expiration boundary.
func (e *Entity) ExpiresAt() time.Time {
	if e == nil {
		return time.Time{}
	}

	return e.expires
}

// Role returns a supported role only while both the entity and role are unexpired at the
// supplied time.
func (e *Entity) Role(kind RoleType, at time.Time) (*Role, error) {
	if e == nil || at.IsZero() || !at.Before(e.expires) {
		return nil, ErrExpired
	}

	r := e.roles[kind]
	if r == nil {
		return nil, ErrMetadata
	}

	if !at.Before(r.expires) {
		return nil, ErrExpired
	}

	return r, nil
}

// Snapshot retains immutable metadata accepted under explicit trust and expiration
// policy.
type Snapshot struct {
	entities      map[string]*Entity
	order         []*Entity
	authenticated bool
	expires       time.Time
}

// ParseTrusted is explicitly for bytes authenticated OUTSIDE this library
// (e.g. an operator-provisioned file). It does not validate any ds:Signature.
// Do not feed an unauthenticated network response into this function.
func ParseTrusted(ctx context.Context, raw []byte, at time.Time, o Options) (*Snapshot, error) {
	return ParseTrustedReader(ctx, bytes.NewReader(raw), at, o)
}

// ParseTrustedReader parses metadata authenticated outside this library. It
// incrementally constructs a complete XML snapshot, performs no signature
// authentication and leaves src open.
func ParseTrustedReader(ctx context.Context, src io.Reader, at time.Time, o Options) (*Snapshot, error) {
	o, e := normalize(o)
	if e != nil {
		return nil, e
	}

	if ctx == nil || nilcheck.IsNil(src) || at.IsZero() {
		return nil, ErrMetadata
	}

	d, e := document.ParseReader(ctx, src, xmlutil.XMLLimits(document.Limits{}, o.MaxBytes))
	if e != nil {
		if errors.Is(e, document.ErrLimit) {
			return nil, errors.Join(ErrMetadata, e)
		}

		return nil, e
	}

	return parse(ctx, d, at, o)
}

// AuthenticatedSignature returns whether the metadata snapshot was authenticated by
// Verify.
func (s *Snapshot) AuthenticatedSignature() bool { return s != nil && s.authenticated }

// ExpiresAt returns the exclusive expiration boundary.
func (s *Snapshot) ExpiresAt() time.Time {
	if s == nil {
		return time.Time{}
	}

	return s.expires
}

// Find returns an entity only while both the snapshot and entity are unexpired at the
// supplied time.
func (s *Snapshot) Find(id string, at time.Time) (*Entity, error) {
	if s == nil || at.IsZero() || !at.Before(s.expires) {
		return nil, ErrExpired
	}

	e := s.entities[id]
	if e == nil {
		return nil, ErrMetadata
	}

	if !at.Before(e.expires) {
		return nil, ErrExpired
	}

	return e, nil
}

// Entities returns an owned slice of immutable metadata entities in source order.
func (s *Snapshot) Entities() []*Entity {
	if s == nil {
		return nil
	}

	return append([]*Entity(nil), s.order...)
}

// Options sets metadata parsing budgets, endpoint restrictions and signature
// algorithms.
type Options struct {
	// MaxBytes bounds metadata XML; zero selects 2 MiB, with a 16 MiB maximum.
	MaxBytes int
	// MaxEntities bounds entity descriptors; zero selects 128, with a maximum of 4096.
	MaxEntities int
	// MaxKeysPerRole bounds role keys; zero selects 8, with a maximum of 16.
	MaxKeysPerRole int
	// MaxEndpointsPerRole bounds role endpoints; zero selects 32, with a maximum of 128.
	MaxEndpointsPerRole int
	// MaxLifetime caps cached validity from the verification time; zero selects
	// 24 hours, with a 30-day maximum. Earlier declared expiry still applies.
	MaxLifetime time.Duration
	// AllowHTTP permits HTTP endpoints; false requires HTTPS.
	AllowHTTP bool
	// Policy sets metadata signature algorithms and key limits. Zero selects
	// xmldsig.DefaultPolicy.
	Policy xmldsig.Policy
}

// Verifier authenticates metadata against its own copy of explicitly trusted public
// keys.
type Verifier struct {
	keys []crypto.PublicKey
	o    Options
}

// NewVerifier snapshots explicitly trusted metadata signer keys and validates metadata
// policy.
func NewVerifier(config Config) (*Verifier, error) {
	o, e := normalize(config.Options)
	if e != nil {
		return nil, e
	}

	ks, e := xmlsig.CloneKeys(config.TrustedKeys)
	if e != nil {
		return nil, e
	}

	return &Verifier{keys: ks, o: o}, nil
}

// Verify authenticates root coverage with an explicitly trusted key, then parses metadata
// and expiration constraints.
func (v *Verifier) Verify(ctx context.Context, raw []byte, at time.Time) (*Snapshot, error) {
	return v.VerifyReader(ctx, bytes.NewReader(raw), at)
}

// VerifyReader authenticates metadata read incrementally from src. It retains
// the complete XML tree and parsed snapshot, leaves src open and returns no
// snapshot until signatures and expiration constraints have passed.
func (v *Verifier) VerifyReader(ctx context.Context, src io.Reader, at time.Time) (*Snapshot, error) {
	if v == nil || ctx == nil || nilcheck.IsNil(src) || at.IsZero() {
		return nil, ErrMetadata
	}

	d, e := document.ParseReader(ctx, src, xmlutil.XMLLimits(document.Limits{}, v.o.MaxBytes))
	if e != nil {
		if errors.Is(e, document.ErrLimit) {
			return nil, errors.Join(ErrMetadata, e)
		}

		return nil, e
	}

	return v.verifyDocument(ctx, d, at)
}

func (v *Verifier) verifyDocument(ctx context.Context, d *document.Document, at time.Time) (*Snapshot, error) {
	if _, e := xmlsig.Verify(ctx, d, d.Root(), v.keys, v.o.Policy); e != nil {
		return nil, e
	}

	s, e := parse(ctx, d, at, v.o)
	if e != nil {
		return nil, e
	}

	s.authenticated = true

	return s, nil
}

// Config supplies metadata signer keys and parsing policy. Construction copies
// TrustedKeys. Embedded metadata keys cannot expand the trusted signer set.
type Config struct {
	// TrustedKeys supplies the explicit metadata signer keys. Embedded keys never extend
	// this set.
	TrustedKeys []crypto.PublicKey
	// Options sets metadata parsing, endpoint and signature policy.
	Options Options
}

type key struct {
	use  string
	der  []byte
	spki []byte
}

func normalize(o Options) (Options, error) {
	if o.MaxBytes == 0 {
		o.MaxBytes = 2 << 20
	}

	if o.MaxEntities == 0 {
		o.MaxEntities = 128
	}

	if o.MaxKeysPerRole == 0 {
		o.MaxKeysPerRole = 8
	}

	if o.MaxEndpointsPerRole == 0 {
		o.MaxEndpointsPerRole = 32
	}

	if o.MaxLifetime == 0 {
		o.MaxLifetime = 24 * time.Hour
	}

	if o.MaxBytes < 1 || o.MaxBytes > 16<<20 || o.MaxEntities < 1 || o.MaxEntities > 4096 || o.MaxKeysPerRole < 1 || o.MaxKeysPerRole > 16 || o.MaxEndpointsPerRole < 1 || o.MaxEndpointsPerRole > 128 || o.MaxLifetime <= 0 || o.MaxLifetime > 30*24*time.Hour {
		return o, ErrMetadata
	}

	o.Policy = xmlsig.ClonePolicy(o.Policy)

	return o, nil
}

func expiry(e document.Element, at, parent time.Time) (time.Time, error) {
	out := parent

	if s := xmlutil.Attr(e, nameValidUntil); s != "" {
		t, er := profile.ParseTime(s)
		if er != nil {
			return time.Time{}, er
		}

		if t.Before(out) {
			out = t
		}
	}

	if s := xmlutil.Attr(e, nameCacheDuration); s != "" {
		d, er := profile.Duration(s)
		if er != nil {
			return time.Time{}, er
		}

		t := at.Add(d)
		if t.Before(out) {
			out = t
		}
	}

	if !at.Before(out) {
		return time.Time{}, ErrExpired
	}

	return out, nil
}

func parse(ctx context.Context, d *document.Document, at time.Time, o Options) (*Snapshot, error) {
	snapshot := &Snapshot{entities: map[string]*Entity{}, expires: at.Add(o.MaxLifetime)}

	expires, err := expiry(d.Root(), at, snapshot.expires)
	if err != nil {
		return nil, err
	}

	snapshot.expires = expires

	parser := metadataParser{ctx: ctx, at: at, options: o, snapshot: snapshot}
	if err := parser.visit(d.Root(), snapshot.expires, 0); err != nil {
		return nil, err
	}

	return snapshot, nil
}

type metadataParser struct {
	ctx      context.Context
	at       time.Time
	options  Options
	snapshot *Snapshot
}

func (p *metadataParser) visit(element document.Element, parent time.Time, depth int) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}

	if depth > 8 {
		return ErrMetadata
	}

	expires, err := expiry(element, p.at, parent)
	if err != nil {
		return err
	}

	if element.Name() == xmlutil.Name(Namespace, "EntitiesDescriptor") {
		return p.visitGroup(element, expires, depth)
	}

	return p.visitEntity(element, expires)
}

func (p *metadataParser) visitGroup(element document.Element, expires time.Time, depth int) error {
	if xmlutil.Attrs(element, nil, []string{"ID", "Name", nameValidUntil, nameCacheDuration}) != nil {
		return ErrMetadata
	}

	if id := xmlutil.Attr(element, "ID"); id != "" && !profile.ID(id) {
		return ErrMetadata
	}

	children, err := xmlutil.Children(element)
	if err != nil {
		return err
	}

	count := 0

	for _, child := range children {
		switch child.Name() {
		case xmlutil.Name(Namespace, "EntityDescriptor"), xmlutil.Name(Namespace, "EntitiesDescriptor"):
			if err := p.visit(child, expires, depth+1); err != nil {
				return err
			}

			count++
		case xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature), xmlutil.Name(Namespace, "Extensions"):
			// Protected metadata content is not interpreted or fetched.
		default:
			return ErrMetadata
		}
	}

	if count == 0 {
		return ErrMetadata
	}

	return nil
}

func (p *metadataParser) visitEntity(element document.Element, expires time.Time) error {
	if element.Name() != xmlutil.Name(Namespace, "EntityDescriptor") || xmlutil.Attrs(element, []string{"entityID"}, []string{"ID", nameValidUntil, nameCacheDuration}) != nil {
		return ErrMetadata
	}

	id := xmlutil.Attr(element, "entityID")
	if !profile.URI(id) || p.snapshot.entities[id] != nil || len(p.snapshot.entities) >= p.options.MaxEntities {
		return ErrMetadata
	}

	if xmlID := xmlutil.Attr(element, "ID"); xmlID != "" && !profile.ID(xmlID) {
		return ErrMetadata
	}

	entity := &Entity{id: id, expires: expires, roles: map[RoleType]*Role{}}

	children, err := xmlutil.Children(element)
	if err != nil {
		return err
	}

	if err := p.readEntityRoles(entity, children); err != nil {
		return err
	}

	if len(entity.roles) == 0 {
		return ErrMetadata
	}

	p.snapshot.entities[id] = entity
	p.snapshot.order = append(p.snapshot.order, entity)

	return nil
}

func (p *metadataParser) readEntityRoles(entity *Entity, children []document.Element) error {
	for _, child := range children {
		switch child.Name() {
		case xmlutil.Name(Namespace, string(ServiceProvider)), xmlutil.Name(Namespace, string(IdentityProvider)):
			kind := RoleType(child.Name().Local)
			if entity.roles[kind] != nil {
				return ErrMetadata
			}

			role, err := parseRole(p.ctx, child, p.at, entity.expires, p.options)
			if err != nil {
				return err
			}

			if role != nil {
				entity.roles[kind] = role
			}
		case xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature), xmlutil.Name(Namespace, "Extensions"), xmlutil.Name(Namespace, "Organization"), xmlutil.Name(Namespace, "ContactPerson"), xmlutil.Name(Namespace, "AdditionalMetadataLocation"):
			// Protected metadata content is not interpreted or fetched.
		default:
			return fmt.Errorf("%w: unsupported role/content %s", ErrMetadata, child.Name().Local)
		}
	}

	return nil
}

func parseRole(ctx context.Context, element document.Element, at, parent time.Time, o Options) (*Role, error) {
	if xmlutil.Attrs(element, []string{"protocolSupportEnumeration"}, []string{"ID", nameValidUntil, nameCacheDuration, "errorURL", "AuthnRequestsSigned", "WantAuthnRequestsSigned", "WantAssertionsSigned"}) != nil {
		return nil, ErrMetadata
	}

	if !roleSupportsProtocol(element) {
		return nil, nil
	}

	expires, err := expiry(element, at, parent)
	if err != nil {
		return nil, err
	}

	role := &Role{kind: RoleType(element.Name().Local), expires: expires, endpoints: map[string][]Endpoint{}}
	if err := readRoleSigningFlags(element, role); err != nil {
		return nil, err
	}

	children, err := xmlutil.Children(element)
	if err != nil {
		return nil, err
	}

	if err := readRoleContent(ctx, role, children, o); err != nil {
		return nil, err
	}

	if err := validateRoleEndpoints(role); err != nil {
		return nil, err
	}

	if role.kind == IdentityProvider && len(role.endpoints[SingleSignOnService]) == 0 || role.kind == ServiceProvider && len(role.endpoints[AssertionConsumerService]) == 0 {
		return nil, ErrMetadata
	}

	return role, nil
}

func roleSupportsProtocol(element document.Element) bool {
	for protocol := range strings.FieldsSeq(xmlutil.Attr(element, "protocolSupportEnumeration")) {
		if protocol == Protocol {
			return true
		}
	}

	return false
}

func readRoleSigningFlags(element document.Element, role *Role) error {
	var err error

	role.authnSigned, err = xmlutil.BoolAttr(element, "AuthnRequestsSigned")
	if err != nil {
		return err
	}

	role.wantAuthnSigned, err = xmlutil.BoolAttr(element, "WantAuthnRequestsSigned")
	if err != nil {
		return err
	}

	role.wantAssertionsSigned, err = xmlutil.BoolAttr(element, "WantAssertionsSigned")

	return err
}

func readRoleContent(ctx context.Context, role *Role, children []document.Element, o Options) error {
	endpointCount := 0

	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return err
		}

		if child.Name().Space != Namespace && child.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
			return ErrMetadata
		}

		switch child.Name().Local {
		case "KeyDescriptor":
			if err := appendRoleKeys(ctx, role, child, o.MaxKeysPerRole); err != nil {
				return err
			}
		case nameNameIDFormat:
			if err := appendRoleNameIDFormat(role, child); err != nil {
				return err
			}
		case SingleSignOnService, SingleLogoutService, AssertionConsumerService, ArtifactResolutionService, ManageNameIDService, NameIDMappingService:
			endpointCount++
			if endpointCount > o.MaxEndpointsPerRole {
				return ErrMetadata
			}

			endpoint, err := parseEndpoint(child, o)
			if err != nil {
				return err
			}

			role.endpoints[child.Name().Local] = append(role.endpoints[child.Name().Local], endpoint)
		case lexicon.DSigElementSignature, "Extensions", "Organization", "ContactPerson", "AttributeConsumingService", "AttributeProfile", "Attribute":
			// Protected role content is not interpreted.
		default:
			return ErrMetadata
		}
	}

	return nil
}

func appendRoleKeys(ctx context.Context, role *Role, descriptor document.Element, limit int) error {
	if len(role.keys) >= limit {
		return ErrMetadata
	}

	keys, err := parseKey(ctx, descriptor)
	if err != nil {
		return err
	}

	role.keys = append(role.keys, keys...)
	if len(role.keys) > limit {
		return ErrMetadata
	}

	return nil
}

func appendRoleNameIDFormat(role *Role, element document.Element) error {
	format, err := xmlutil.Simple(element, 2048)
	if err != nil || !profile.URI(format) {
		return ErrMetadata
	}

	role.formats = append(role.formats, format)
	if len(role.formats) > 32 {
		return ErrMetadata
	}

	return nil
}

func parseEndpoint(c document.Element, o Options) (Endpoint, error) {
	indexed := c.Name().Local == AssertionConsumerService || c.Name().Local == ArtifactResolutionService
	required := []string{"Binding", "Location"}
	optional := []string{"ResponseLocation"}

	if indexed {
		required = append(required, "index")
		optional = append(optional, "isDefault")
	}

	if xmlutil.Attrs(c, required, optional) != nil || !xmlutil.EmptyContent(c) {
		return Endpoint{}, ErrMetadata
	}

	e := Endpoint{Binding: xmlutil.Attr(c, "Binding"), Location: xmlutil.Attr(c, "Location"), ResponseLocation: xmlutil.Attr(c, "ResponseLocation"), Indexed: indexed}
	if !profile.URI(e.Binding) || !profile.Endpoint(e.Location, o.AllowHTTP) || e.ResponseLocation != "" && !profile.Endpoint(e.ResponseLocation, o.AllowHTTP) {
		return Endpoint{}, ErrMetadata
	}

	if indexed {
		n, err := profile.Index(xmlutil.Attr(c, "index"))
		if err != nil {
			return Endpoint{}, ErrMetadata
		}

		e.Index = n
		_, e.DefaultSet = c.Attribute(document.Name{Local: "isDefault"})

		e.Default, err = xmlutil.BoolAttr(c, "isDefault")
		if err != nil {
			return Endpoint{}, err
		}
	}

	return e, nil
}

func parseKey(ctx context.Context, c document.Element) ([]key, error) {
	if xmlutil.Attrs(c, nil, []string{"use"}) != nil {
		return nil, ErrMetadata
	}

	use := xmlutil.Attr(c, "use")
	if use != "" && use != "signing" && use != "encryption" {
		return nil, ErrMetadata
	}

	cs, e := xmlutil.Children(c)
	if e != nil || len(cs) == 0 || cs[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementKeyInfo) {
		return nil, ErrMetadata
	}

	for _, extra := range cs[1:] {
		if extra.Name() != xmlutil.Name(Namespace, "EncryptionMethod") {
			return nil, ErrMetadata
		}
	}

	if len(cs[0].Attributes()) != 0 {
		return nil, ErrMetadata
	}

	ks := cs[0].Children()
	if len(ks) != 1 || ks[0].Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementX509Data) {
		return nil, ErrMetadata
	}

	var out []key
	// This profile requires one certificate per descriptor. It must not silently
	// authorize every CA key from a supplied certificate-chain bag.
	if len(ks[0].Children()) != 1 {
		return nil, ErrMetadata
	}

	for _, x := range ks[0].Children() {
		if x.Name() != xmlutil.Name(xmlutil.DS, lexicon.DSigElementX509Certificate) {
			return nil, ErrMetadata
		}

		if len(x.Attributes()) != 0 {
			return nil, ErrMetadata
		}

		_, node := tree.Unwrap(x)

		b, e := tree.DecodeBase64(ctx, node, 48<<10, 32<<10)
		if e != nil {
			return nil, errors.Join(ErrMetadata, e)
		}

		cert, e := x509cert.ParseWithMaxBytes(b, len(b))
		if e != nil {
			return nil, ErrMetadata
		}

		pub, e := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if e != nil {
			return nil, e
		}

		out = append(out, key{use: use, der: b, spki: pub})
	}

	if len(out) == 0 {
		return nil, ErrMetadata
	}

	return out, nil
}

func validateRoleEndpoints(role *Role) error {
	for _, endpoints := range role.endpoints {
		seen := map[uint16]struct{}{}
		defaults := 0

		for _, endpoint := range endpoints {
			if endpoint.Indexed {
				if _, exists := seen[endpoint.Index]; exists {
					return ErrMetadata
				}

				seen[endpoint.Index] = struct{}{}
			}

			if endpoint.Default {
				defaults++
			}
		}

		if defaults > 1 {
			return ErrMetadata
		}
	}

	return nil
}
