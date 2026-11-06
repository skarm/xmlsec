package protocol

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
	"github.com/skarm/xmlsec/xmlenc"
)

// XML Encryption local names used by the restricted SAML encryption grammar.
// Callers separately require the XML Encryption namespace and allowed child order.
const (
	xmlNameCipherData           = "CipherData"
	xmlNameEncryptedData        = "EncryptedData"
	xmlNameEncryptedKey         = "EncryptedKey"
	xmlNameEncryptionMethod     = "EncryptionMethod"
	xmlNameEncryptionProperties = "EncryptionProperties"
)

const nameEncryptedType = lexicon.SecurityAttrType

// EncryptionTargets selects SAML elements to encrypt or require encrypted.
type EncryptionTargets uint8

const (
	// EncryptAssertion encrypts the complete assertion after its signature.
	EncryptAssertion EncryptionTargets = 1 << iota
	// EncryptNameID encrypts NameID before the containing assertion is signed.
	EncryptNameID
	// EncryptAttributes encrypts each Attribute before the assertion is signed.
	EncryptAttributes
)

// ErrEncryption reports rejected encrypted SAML data without exposing whether a
// key, padding, authentication tag or decrypted XML was incorrect.
var ErrEncryption = errors.New("SAML encryption rejected")

// EncryptionOptions selects explicit targets, recipient and algorithms. Zero
// Data uses AES-256-GCM/RSA-OAEP-SHA256. CBC needs explicit legacy permission and
// an enclosing authenticated signature. No external ciphertext is accepted.
type EncryptionOptions struct {
	// Targets selects the SAML elements to encrypt; at least one target is
	// required.
	Targets EncryptionTargets
	// Recipient is mandatory at protocol level. The IdP may select it from
	// authenticated SP encryption metadata when this field is nil.
	Recipient *rsa.PublicKey
	// Data selects data and key transport algorithms. Zero uses AES-256-GCM with
	// RSA-OAEP-SHA256.
	Data xmlenc.Options
}

// DecryptionOptions supplies a bounded, application-owned RSA key ring. Keys and
// their providers must support concurrent calls. XML key descriptions never add
// keys or trust; inline/sibling EncryptedKey alternatives use only this ring.
type DecryptionOptions struct {
	// Keys supplies the trusted, application-owned RSA private-key providers to
	// try.
	Keys []crypto.Decrypter
	// Data fixes the expected algorithms; received XML cannot broaden policy.
	Data xmlenc.Options
	// MaxDecryptions bounds private-key attempts across the entire response.
	// Zero selects 64; the maximum is 1024.
	MaxDecryptions int
}

type decryptionState struct {
	// options retains the snapshotted key ring and algorithm policy.
	options DecryptionOptions
	// remaining shares the private-key attempt budget across the complete message.
	remaining int
}

func validEncryptionTargets(targets EncryptionTargets) bool {
	return targets&^(EncryptAssertion|EncryptNameID|EncryptAttributes) == 0
}

// CloneEncryption validates and snapshots producer policy without requiring a
// recipient. High-level IdPs obtain that recipient from trusted metadata.
func CloneEncryption(o *EncryptionOptions) (*EncryptionOptions, error) {
	if o == nil {
		return nil, nil
	}

	if o.Targets == 0 || !validEncryptionTargets(o.Targets) || o.Data.External != nil {
		return nil, ErrEncryption
	}

	p := *o

	p.Data = cloneCipherOptions(p.Data)
	if p.Recipient != nil {
		if !validRSARecipient(p.Recipient) {
			return nil, ErrEncryption
		}

		der, err := x509.MarshalPKIXPublicKey(p.Recipient)
		if err != nil {
			return nil, ErrEncryption
		}

		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, ErrEncryption
		}

		public, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, ErrEncryption
		}

		p.Recipient = public
	}

	return &p, nil
}

// CloneDecryption validates and snapshots the key-ring slice and cipher policy.
// Private providers remain caller-owned, as with SigningKey.Key.
func CloneDecryption(o *DecryptionOptions) (*DecryptionOptions, error) {
	const (
		defaultDecryptionAttempts = 64
		maximumDecryptionAttempts = 1024
		maximumDecryptionKeys     = 16
	)

	if o == nil {
		return nil, nil
	}

	if len(o.Keys) == 0 || len(o.Keys) > maximumDecryptionKeys || o.Data.External != nil || o.MaxDecryptions < 0 || o.MaxDecryptions > maximumDecryptionAttempts {
		return nil, ErrEncryption
	}

	p := *o
	p.Keys = append([]crypto.Decrypter(nil), o.Keys...)

	p.Data = cloneCipherOptions(p.Data)
	for _, key := range p.Keys {
		if nilcheck.IsNil(key) {
			return nil, ErrEncryption
		}

		public, ok := key.Public().(*rsa.PublicKey)
		if !ok || !validRSARecipient(public) {
			return nil, ErrEncryption
		}
	}

	if p.MaxDecryptions == 0 {
		p.MaxDecryptions = defaultDecryptionAttempts
	}

	return &p, nil
}

func validRSARecipient(key *rsa.PublicKey) bool {
	const (
		maximumRSAExponent      = 0x7fffffff
		maximumRSARecipientBits = 16384
		minimumRSAExponent      = 3
		minimumRSARecipientBits = 2048
	)

	return key != nil && key.N != nil && key.N.Sign() > 0 && key.N.Bit(0) != 0 && key.N.BitLen() >= minimumRSARecipientBits && key.N.BitLen() <= maximumRSARecipientBits && key.E >= minimumRSAExponent && key.E%2 != 0 && key.E <= maximumRSAExponent
}

func cloneCipherOptions(o xmlenc.Options) xmlenc.Options {
	if o.OAEP != nil {
		parameters := *o.OAEP
		parameters.Label = bytes.Clone(parameters.Label)
		o.OAEP = &parameters
	}

	return o
}

func newDecryptionState(o *DecryptionOptions) (*decryptionState, error) {
	p, err := CloneDecryption(o)
	if err != nil || p == nil {
		return nil, err
	}

	return &decryptionState{options: *p, remaining: p.MaxDecryptions}, nil
}

func replaceSAML(ctx context.Context, d *document.Document, old document.Element, replacement *tree.Node) (*document.Document, error) {
	owner, node := tree.Unwrap(old)
	if owner != d {
		return nil, ErrProfile
	}

	draft, err := tree.ReplaceDraft(ctx, d, node, replacement)
	if err != nil {
		return nil, err
	}

	return tree.Reparse(ctx, draft, tree.Policy(d))
}

func encryptSAML(ctx context.Context, d *document.Document, selected document.Element, wrapper string, options *EncryptionOptions) (*document.Document, error) {
	encrypted, data, err := xmlenc.EncryptElement(ctx, d, selected, options.Recipient, options.Data)
	if err != nil {
		return nil, err
	}

	_, node := tree.Unwrap(data)

	container := xmlutil.Node(prefixAssertion, AssertionNamespace, wrapper)
	if wrapper == xmlNameNewEncryptedID {
		container = xmlutil.Node(prefixProtocol, ProtocolNamespace, wrapper)
	}

	if selected == d.Root() {
		container.NS = []tree.Namespace{{Prefix: container.Prefix, URI: container.Name.Space}}
	}

	xmlutil.Add(container, tree.ExtractSubtree(node))

	return replaceSAML(ctx, encrypted, data, container)
}

func cbcCipher(o xmlenc.Options) bool {
	return o.DataAlgorithm == xmlenc.AES128CBC || o.DataAlgorithm == xmlenc.AES192CBC || o.DataAlgorithm == xmlenc.AES256CBC || o.DataAlgorithm == xmlenc.TripleDESCBC
}

// decryptSAML is called only after the containing signature is verified, except
// explicitly allowed unsigned envelopes using authenticated GCM data encryption.
func (s *decryptionState) decryptSAML(ctx context.Context, d *document.Document, wrapper document.Element, expected string, authenticated bool) (*document.Document, error) {
	return s.decryptSAMLName(ctx, d, wrapper, xmlutil.Name(AssertionNamespace, expected), authenticated)
}

func (s *decryptionState) decryptSAMLName(ctx context.Context, d *document.Document, wrapper document.Element, expected document.Name, authenticated bool) (*document.Document, error) {
	if s == nil || (cbcCipher(s.options.Data) || s.options.Data.KeyTransportAlgorithm == xmlenc.RSA15) && !authenticated || xmlutil.Attrs(wrapper, nil, nil) != nil {
		return nil, ErrEncryption
	}

	data, candidates, err := encryptedSAMLRecipients(wrapper)
	if err != nil {
		return nil, err
	}

	for _, candidate := range candidates {
		private, selected, err := samlCipherCandidate(ctx, wrapper, data, candidate)
		if err != nil {
			return nil, encryptionFailure(ctx, err)
		}

		for _, key := range s.options.Keys {
			if s.remaining == 0 {
				return nil, errors.Join(ErrEncryption, document.ErrLimit)
			}

			s.remaining--

			_, plain, err := xmlenc.DecryptElement(ctx, private, selected, key, s.options.Data)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			if err != nil {
				continue
			}

			if plain.Name() != expected {
				return nil, ErrEncryption
			}

			_, node := tree.Unwrap(plain)

			return replaceSAML(ctx, d, wrapper, tree.ExtractSubtree(node))
		}
	}

	return nil, ErrEncryption
}

func encryptedSAMLRecipients(wrapper document.Element) (document.Element, []document.Element, error) {
	const (
		maximumEncryptedKeyCandidates     = 16
		maximumEncryptedRecipientChildren = 17
	)

	children, err := xmlutil.Children(wrapper)
	if err != nil || len(children) == 0 || len(children) > maximumEncryptedRecipientChildren || children[0].Name() != xmlutil.Name(xmlenc.Namespace, xmlNameEncryptedData) {
		return document.Element{}, nil, ErrEncryption
	}

	data := children[0]
	if err := samlEncryptedData(data); err != nil {
		return document.Element{}, nil, err
	}

	typ, present := data.Attribute(document.Name{Local: nameEncryptedType})
	if present && typ != xmlenc.ElementType {
		return document.Element{}, nil, ErrEncryption
	}

	var candidates []document.Element

	for _, child := range data.Children() {
		if child.Name() == xmlutil.Name(xmlutil.DS, lexicon.DSigElementKeyInfo) {
			for _, key := range child.Children() {
				if key.Name() == xmlutil.Name(xmlenc.Namespace, xmlNameEncryptedKey) {
					candidates = append(candidates, key)
				}
			}
		}
	}

	for _, child := range children[1:] {
		if child.Name() != xmlutil.Name(xmlenc.Namespace, xmlNameEncryptedKey) {
			return document.Element{}, nil, ErrEncryption
		}

		candidates = append(candidates, child)
	}

	if len(candidates) == 0 || len(candidates) > maximumEncryptedKeyCandidates {
		return document.Element{}, nil, ErrEncryption
	}

	return data, candidates, nil
}

func encryptionFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if errors.Is(err, document.ErrLimit) {
		return errors.Join(ErrEncryption, document.ErrLimit)
	}

	return ErrEncryption
}

// The SAML wrapper supplies the encrypted-key candidates. KeyInfo is a hint,
// not a source of authority: retain each candidate's cryptographic method/data
// and evaluate it only with explicitly configured private keys. ReferenceList,
// when present, must actually designate this EncryptedData.
func samlCipherCandidate(ctx context.Context, wrapper, data, key document.Element) (*document.Document, document.Element, error) {
	const (
		prefixEncryption = "xenc"
	)

	method, cipher, err := samlEncryptedKeyMaterial(key, xmlutil.Attr(data, lexicon.SecurityAttrID))
	if err != nil {
		return nil, document.Element{}, err
	}

	_, original := tree.Unwrap(data)
	copyData := tree.ExtractSubtree(original)
	copyData.Children = nil
	// Id, MimeType and Encoding describe the encrypted object. They do not
	// select algorithms or keys and need not enter the closed cipher profile.
	copyData.Attrs = []tree.Attribute{{Name: document.Name{Local: nameEncryptedType}, Value: xmlenc.ElementType}}
	for _, child := range original.Children {
		if child.Kind == tree.ElementNode && (child.Name == xmlutil.Name(xmlutil.DS, lexicon.DSigElementKeyInfo) || child.Name == xmlutil.Name(xmlenc.Namespace, xmlNameEncryptionProperties)) {
			continue
		}

		copyData.Children = append(copyData.Children, child)
	}

	info := xmlutil.Node(lexicon.PrefixDSig, xmlutil.DS, lexicon.DSigElementKeyInfo)
	info.NS = []tree.Namespace{{Prefix: lexicon.PrefixDSig, URI: xmlutil.DS}}
	wrapped := xmlutil.Node(prefixEncryption, xmlenc.Namespace, xmlNameEncryptedKey)
	wrapped.NS = []tree.Namespace{{Prefix: prefixEncryption, URI: xmlenc.Namespace}}
	xmlutil.Add(wrapped, method)
	xmlutil.Add(wrapped, cipher)
	xmlutil.Add(info, wrapped)
	// EncryptionMethod precedes KeyInfo; CipherData follows it.
	insert := 0

	for i, child := range copyData.Children {
		if child.Kind == tree.ElementNode && child.Name == xmlutil.Name(xmlenc.Namespace, xmlNameEncryptionMethod) {
			insert = i + 1
		}
	}

	copyData.Children = append(copyData.Children, nil)
	copy(copyData.Children[insert+1:], copyData.Children[insert:])
	copyData.Children[insert] = info
	info.Parent = copyData
	_, parent := tree.Unwrap(wrapper)
	container := tree.ExtractSubtree(parent)
	container.Children = []*tree.Node{copyData}
	copyData.Parent = container
	limits := tree.Policy(documentOwner(wrapper))

	private, err := tree.Reparse(ctx, tree.FromNodes([]*tree.Node{container}, limits), limits)
	if err != nil {
		return nil, document.Element{}, err
	}

	selected, err := xmlutil.Direct(private.Root(), xmlutil.Name(xmlenc.Namespace, xmlNameEncryptedData))

	return private, selected, err
}

func samlEncryptedKeyMaterial(key document.Element, dataID string) (*tree.Node, *tree.Node, error) {
	const (
		keyAfterCarriedNameState    = 5
		keyAfterCipherDataState     = 3
		keyAfterKeyInfoState        = 2
		keyAfterMethodState         = 1
		keyAfterReferencesState     = 4
		keyInitialState             = 0
		minimumEncryptedKeyChildren = 2
		xmlNameCarriedKeyName       = "CarriedKeyName"
		xmlNameReferenceList        = "ReferenceList"
	)

	if xmlutil.Attrs(key, nil, []string{lexicon.SecurityAttrID, nameEncryptedType, lexicon.SecurityAttrMimeType, lexicon.SecurityAttrEncoding, nameRecipient}) != nil {
		return nil, nil, ErrEncryption
	}

	cs, err := xmlutil.Children(key)
	if err != nil || len(cs) < minimumEncryptedKeyChildren || cs[0].Name() != xmlutil.Name(xmlenc.Namespace, xmlNameEncryptionMethod) {
		return nil, nil, ErrEncryption
	}

	var method, cipher *tree.Node

	position := keyInitialState

	for _, child := range cs {
		_, node := tree.Unwrap(child)
		switch child.Name() {
		case xmlutil.Name(xmlenc.Namespace, xmlNameEncryptionMethod):
			if position != keyInitialState {
				return nil, nil, ErrEncryption
			}

			method, position = tree.ExtractSubtree(node), keyAfterMethodState
		case xmlutil.Name(xmlutil.DS, lexicon.DSigElementKeyInfo):
			if position != keyAfterMethodState {
				return nil, nil, ErrEncryption
			}

			position = keyAfterKeyInfoState
		case xmlutil.Name(xmlenc.Namespace, xmlNameCipherData):
			if position != keyAfterMethodState && position != keyAfterKeyInfoState {
				return nil, nil, ErrEncryption
			}

			cipher, position = tree.ExtractSubtree(node), keyAfterCipherDataState
		case xmlutil.Name(xmlenc.Namespace, xmlNameReferenceList):
			if position != keyAfterCipherDataState || !samlKeyReferences(child, dataID) {
				return nil, nil, ErrEncryption
			}

			position = keyAfterReferencesState
		case xmlutil.Name(xmlenc.Namespace, xmlNameCarriedKeyName):
			if position < keyAfterCipherDataState || position > keyAfterReferencesState {
				return nil, nil, ErrEncryption
			}

			position = keyAfterCarriedNameState
		default:
			return nil, nil, ErrEncryption
		}
	}

	if method == nil || cipher == nil {
		return nil, nil, ErrEncryption
	}

	return method, cipher, nil
}

func samlEncryptedData(data document.Element) error {
	const (
		dataAfterCipherDataState = 3
		dataAfterKeyInfoState    = 2
		dataAfterMethodState     = 1
		dataAfterPropertiesState = 4
		dataInitialState         = 0
	)

	if xmlutil.Attrs(data, nil, []string{lexicon.SecurityAttrID, nameEncryptedType, lexicon.SecurityAttrMimeType, lexicon.SecurityAttrEncoding}) != nil {
		return ErrEncryption
	}

	children, err := xmlutil.Children(data)
	if err != nil {
		return ErrEncryption
	}

	position, hasCipher := dataInitialState, false

	for _, child := range children {
		switch child.Name() {
		case xmlutil.Name(xmlenc.Namespace, xmlNameEncryptionMethod):
			if position != dataInitialState {
				return ErrEncryption
			}

			position = dataAfterMethodState
		case xmlutil.Name(xmlutil.DS, lexicon.DSigElementKeyInfo):
			if position > dataAfterMethodState {
				return ErrEncryption
			}

			position = dataAfterKeyInfoState
		case xmlutil.Name(xmlenc.Namespace, xmlNameCipherData):
			if position > dataAfterKeyInfoState {
				return ErrEncryption
			}

			position, hasCipher = dataAfterCipherDataState, true
		case xmlutil.Name(xmlenc.Namespace, xmlNameEncryptionProperties):
			if position != dataAfterCipherDataState {
				return ErrEncryption
			}

			position = dataAfterPropertiesState
		default:
			return ErrEncryption
		}
	}

	if !hasCipher {
		return ErrEncryption
	}

	return nil
}

func documentOwner(element document.Element) *document.Document {
	d, _ := tree.Unwrap(element)
	return d
}

func samlKeyReferences(list document.Element, id string) bool {
	const (
		xmlNameDataReference = "DataReference"
		xmlNameKeyReference  = "KeyReference"
	)

	if id == "" || xmlutil.Attrs(list, nil, nil) != nil {
		return false
	}

	children, err := xmlutil.Children(list)
	if err != nil || len(children) == 0 {
		return false
	}

	found := false

	for _, child := range children {
		if child.Name() != xmlutil.Name(xmlenc.Namespace, xmlNameDataReference) && child.Name() != xmlutil.Name(xmlenc.Namespace, xmlNameKeyReference) || xmlutil.Attrs(child, []string{lexicon.SecurityAttrURI}, nil) != nil {
			return false
		}

		uri := xmlutil.Attr(child, lexicon.SecurityAttrURI)

		value, err := url.PathUnescape(strings.TrimPrefix(uri, "#"))
		if err != nil {
			return false
		}

		found = found || child.Name().Local == xmlNameDataReference && strings.HasPrefix(uri, "#") && value == id
	}

	return found
}

func assertionChild(d *document.Document, local string) (document.Element, error) {
	assertion, err := xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, nameAssertion))
	if err != nil {
		return document.Element{}, err
	}

	return xmlutil.Direct(assertion, xmlutil.Name(AssertionNamespace, local))
}

func encryptAssertionContents(ctx context.Context, d *document.Document, o *EncryptionOptions) (*document.Document, error) {
	if o.Targets&EncryptNameID != 0 {
		subject, err := assertionChild(d, xmlNameSubject)
		if err != nil {
			return nil, err
		}

		name, err := xmlutil.Direct(subject, xmlutil.Name(AssertionNamespace, xmlNameNameID))
		if err != nil {
			return nil, err
		}

		d, err = encryptSAML(ctx, d, name, xmlNameEncryptedID, o)
		if err != nil {
			return nil, err
		}
	}

	if o.Targets&EncryptAttributes != 0 {
		for {
			statement, err := optionalAttributeStatement(d)
			if err != nil || !statement.Valid() {
				return d, err
			}

			var selected document.Element

			for _, child := range statement.Children() {
				if child.Name() == xmlutil.Name(AssertionNamespace, xmlNameAttribute) {
					selected = child
					break
				}
			}

			if !selected.Valid() {
				break
			}

			d, err = encryptSAML(ctx, d, selected, xmlNameEncryptedAttribute, o)
			if err != nil {
				return nil, err
			}
		}
	}

	return d, nil
}

func optionalAttributeStatement(d *document.Document) (document.Element, error) {
	assertion, err := xmlutil.Direct(d.Root(), xmlutil.Name(AssertionNamespace, nameAssertion))
	if err != nil {
		return document.Element{}, err
	}

	var found document.Element

	for _, child := range assertion.Children() {
		if child.Name() == xmlutil.Name(AssertionNamespace, xmlNameAttributeStatement) {
			if found.Valid() {
				return document.Element{}, ErrProfile
			}

			found = child
		}
	}

	return found, nil
}

func decryptAssertionContents(ctx context.Context, d *document.Document, state *decryptionState, require EncryptionTargets, authenticated bool, limits Limits) (*document.Document, EncryptionTargets, error) {
	var targets EncryptionTargets

	subject, err := assertionChild(d, xmlNameSubject)
	if err != nil {
		return nil, 0, err
	}

	children, err := xmlutil.Children(subject)
	if err != nil || len(children) < minimumSubjectChildren || len(children) > maximumSubjectChildren {
		return nil, 0, ErrProfile
	}

	if children[0].Name() == xmlutil.Name(AssertionNamespace, xmlNameEncryptedID) {
		d, err = state.decryptSAML(ctx, d, children[0], xmlNameNameID, authenticated)
		if err != nil {
			return nil, 0, err
		}

		targets |= EncryptNameID
	} else if require&EncryptNameID != 0 {
		return nil, 0, ErrEncryption
	}
	// Inspect all attribute positions before replacing any handles. Reacquire
	// the statement after each immutable snapshot replacement.
	statement, err := optionalAttributeStatement(d)
	if err != nil || !statement.Valid() {
		return d, targets, err
	}

	attributes, err := xmlutil.Children(statement)
	if err != nil || len(attributes) > limits.MaxAttributes {
		return nil, 0, ErrProfile
	}

	for _, attribute := range attributes {
		switch attribute.Name() {
		case xmlutil.Name(AssertionNamespace, xmlNameEncryptedAttribute):
		case xmlutil.Name(AssertionNamespace, xmlNameAttribute):
			if require&EncryptAttributes != 0 {
				return nil, 0, ErrEncryption
			}
		default:
			return nil, 0, ErrProfile
		}
	}

	for {
		statement, err = optionalAttributeStatement(d)
		if err != nil {
			return nil, 0, err
		}

		var selected document.Element

		for _, child := range statement.Children() {
			if child.Name() == xmlutil.Name(AssertionNamespace, xmlNameEncryptedAttribute) {
				selected = child
				break
			}
		}

		if !selected.Valid() {
			break
		}

		d, err = state.decryptSAML(ctx, d, selected, xmlNameAttribute, authenticated)
		if err != nil {
			return nil, 0, err
		}

		targets |= EncryptAttributes
	}

	return d, targets, nil
}
