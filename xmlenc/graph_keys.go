package xmlenc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/des" // #nosec G502 -- Explicit legacy XMLENC key-wrap policy only.
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
)

const (
	// Unqualified recipient label resolved through caller-supplied graph bindings.
	attrRecipient = "Recipient"
	// Logical name carried with an encrypted key for graph resolution. Compare the expected XML
	// Encryption namespace when matching it.
	nameCarriedKeyName = "CarriedKeyName"
	// Reference-list entry targeting encrypted application data. Compare the expected XML Encryption
	// namespace when matching it.
	nameDataReference = "DataReference"
	// XML Encryption 1.1 derived-key node in the explicit key graph. Compare the expected XML
	// Encryption namespace when matching it.
	nameDerivedKey = "DerivedKey"
	// Logical name associated with a derived key. Compare the expected XML Encryption namespace when
	// matching it.
	nameDerivedKeyName = "DerivedKeyName"
	// Wrapped-key node resolved under the configured key-graph policy. Compare the expected XML
	// Encryption namespace when matching it.
	nameEncryptedKey = "EncryptedKey"
	// One metadata record within EncryptionProperties. Compare the expected XML Encryption namespace
	// when matching it.
	nameEncryptionProperty = "EncryptionProperty"
	// Reference-list entry linking to another encrypted key. Compare the expected XML Encryption
	// namespace when matching it.
	nameKeyReference = "KeyReference"
	// Targets associated with one EncryptedKey. Compare the expected XML Encryption namespace when
	// matching it.
	nameReferenceList = "ReferenceList"
)

type graphPlanID struct {
	document  *graphDocument
	node      *tree.Node
	algorithm string
	keyBytes  int
}

type graphKeyPlan struct {
	algorithm string
	keyBytes  int
	sources   []*graphKeyPlan
	material  []byte
	provider  crypto.Decrypter
	oaep      OAEPParameters
	kdf       *ConcatKDFParameters
	wrapped   []byte
	cipher    *graphCipherPlan
	value     []byte
	unwrap    func(context.Context, []byte) ([]byte, error)

	done bool
}

type graphEncryptedFields struct {
	method     document.Element
	keyInfo    document.Element
	cipherData document.Element
	properties document.Element
	references document.Element
	carried    document.Element
}

func graphEncrypted(node graphNode) (graphEncryptedFields, error) {
	// These positions match values below. EncryptedData ends at optional
	// EncryptionProperties; only EncryptedKey may carry the final two fields.
	const (
		encryptionMethodPosition     = 0
		keyInfoPosition              = 1
		cipherDataPosition           = 2
		encryptionPropertiesPosition = 3
		referenceListPosition        = 4
		carriedKeyNamePosition       = 5
	)

	var fields graphEncryptedFields

	element := node.element()

	key := element.Name() == elementName(Namespace, nameEncryptedKey)
	if !key && element.Name() != elementName(Namespace, nameEncryptedData) || !graphAttributes(element, lexicon.SecurityAttrID, lexicon.SecurityAttrType, lexicon.SecurityAttrMimeType, lexicon.SecurityAttrEncoding, attrRecipient) || !key && graphHasAttribute(element, attrRecipient) {
		return fields, ErrFormat
	}

	positions := map[document.Name]int{
		elementName(Namespace, nameEncryptionMethod): encryptionMethodPosition, elementName(SignatureNamespace, lexicon.DSigElementKeyInfo): keyInfoPosition,
		elementName(Namespace, nameCipherData): cipherDataPosition, elementName(Namespace, nameEncryptionProperties): encryptionPropertiesPosition,
		elementName(Namespace, nameReferenceList): referenceListPosition, elementName(Namespace, nameCarriedKeyName): carriedKeyNamePosition,
	}
	values := []*document.Element{&fields.method, &fields.keyInfo, &fields.cipherData, &fields.properties, &fields.references, &fields.carried}
	previous := -1

	for _, child := range node.node.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return fields, ErrFormat
		}
	}

	for _, child := range element.Children() {
		position, known := positions[child.Name()]
		if !known || position <= previous || !key && position > encryptionPropertiesPosition {
			return fields, ErrFormat
		}

		previous = position
		*values[position] = child
	}

	if !fields.cipherData.Valid() {
		return fields, ErrFormat
	}

	if fields.properties.Valid() {
		if err := checkGraphProperties(fields.properties); err != nil {
			return fields, err
		}
	}

	if fields.carried.Valid() {
		if _, err := graphNameText(fields.carried); err != nil {
			return fields, err
		}
	}

	if fields.references.Valid() {
		if _, err := graphReferences(fields.references); err != nil {
			return fields, err
		}
	}

	return fields, nil
}

func checkGraphProperties(properties document.Element) error {
	if !graphAttributes(properties, lexicon.SecurityAttrID) || len(properties.Children()) == 0 {
		return ErrFormat
	}

	_, root := tree.Unwrap(properties)
	for _, child := range root.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return ErrFormat
		}
	}

	for _, property := range properties.Children() {
		if property.Name() != elementName(Namespace, nameEncryptionProperty) || len(property.Children()) == 0 {
			return ErrFormat
		}

		_, node := tree.Unwrap(property)
		for _, attribute := range node.Attrs {
			if attribute.Name.Space != document.XMLNamespace && attribute.Name != (document.Name{Local: lexicon.SecurityAttrID}) && attribute.Name != (document.Name{Local: lexicon.SecurityAttrTarget}) {
				return ErrFormat
			}
		}

		for _, child := range property.Children() {
			if child.Name().Space == "" || child.Name().Space == Namespace {
				return ErrFormat
			}
		}
	}

	return nil
}

func graphReferences(list document.Element) ([]document.Element, error) {
	if !exactAttributes(list) || len(list.Children()) == 0 {
		return nil, ErrFormat
	}

	_, node := tree.Unwrap(list)
	for _, child := range node.Children {
		if child.Kind == tree.TextNode && !xmlSpace(child.Data) {
			return nil, ErrFormat
		}
	}

	children := list.Children()
	for _, child := range children {
		if child.Name() != elementName(Namespace, nameDataReference) && child.Name() != elementName(Namespace, nameKeyReference) || !exactAttributes(child, lexicon.SecurityAttrURI) || !validGraphReference(attributeValue(child, lexicon.SecurityAttrURI)) {
			return nil, ErrFormat
		}

		_, raw := tree.Unwrap(child)
		for _, item := range raw.Children {
			if item.Kind == tree.TextNode && !xmlSpace(item.Data) || item.Kind == tree.ElementNode && (item.Name.Space == "" || item.Name.Space == Namespace) {
				return nil, ErrFormat
			}
		}
	}

	return children, nil
}

func (g *keyGraph) namedMaterial(name, algorithm string, size int) (*graphKeyPlan, error) {
	binding, ok := g.bindings[graphBinding{name, algorithm}]
	if !ok || len(binding.Secret) == 0 {
		return nil, errGraphKeyUnavailable
	}

	if size != 0 && len(binding.Secret) != size {
		return nil, ErrPolicy
	}

	return &graphKeyPlan{material: binding.Secret, keyBytes: len(binding.Secret)}, nil
}

func (g *keyGraph) keyName(node graphNode) (string, bool, error) {
	name := elementName(Namespace, nameCarriedKeyName)
	if node.node.Name == elementName(Namespace11, nameDerivedKey) {
		name = elementName(Namespace11, nameDerivedKeyName)
	}

	for _, child := range node.element().Children() {
		if child.Name() == name {
			value, err := graphNameText(child)
			return value, true, err
		}
	}

	return "", false, nil
}

func (g *keyGraph) consumerKey(node graphNode, info document.Element, algorithm string, size, depth int) (*graphKeyPlan, error) {
	if depth > g.limits.MaxDepth {
		return nil, graphLimitError()
	}

	if err := g.charge(1, 0); err != nil {
		return nil, err
	}

	b := graphSources{graph: g, target: node, algorithm: algorithm, size: size, depth: depth}
	if err := b.keyInfo(info); err != nil {
		return nil, err
	}

	if err := b.references(); err != nil {
		return nil, err
	}

	if depth == 0 {
		for _, candidate := range g.standalone {
			if err := b.add(g.keyPlan(candidate, algorithm, size, depth+1)); err != nil {
				return nil, err
			}
		}
	}

	if len(b.plans) == 0 {
		return nil, errGraphKeyUnavailable
	}

	return &graphKeyPlan{sources: b.plans, keyBytes: size}, nil
}

func (g *keyGraph) keyPlan(node graphNode, consumer string, size, depth int) (*graphKeyPlan, error) {
	identity := graphPlanID{node.document, node.node, consumer, size}
	// A plan still being built is a cycle. Completed plans may be shared, so
	// check the active path separately from the reusable plan cache below.
	if _, exists := g.active[identity]; exists {
		return nil, ErrFormat
	}

	if depth > g.limits.MaxDepth {
		return nil, graphLimitError()
	}

	if existing := g.plans[identity]; existing != nil {
		return existing, nil
	}

	if err := g.charge(1, 0); err != nil {
		return nil, err
	}

	g.active[identity] = struct{}{}
	defer delete(g.active, identity)

	var (
		plan *graphKeyPlan
		err  error
	)
	if node.node.Name == elementName(Namespace11, nameDerivedKey) {
		plan, err = g.derivedPlan(node, size, depth)
	} else if node.node.Name == elementName(Namespace, nameEncryptedKey) {
		plan, err = g.encryptedPlan(node, consumer, size, depth)
	} else {
		return nil, ErrFormat
	}

	if err != nil {
		return nil, err
	}

	g.plans[identity] = plan

	return plan, nil
}

func (g *keyGraph) encryptedPlan(node graphNode, consumer string, size, depth int) (*graphKeyPlan, error) {
	fields, err := graphEncrypted(node)
	if err != nil || !sessionKeySize(size) {
		return nil, errors.Join(ErrFormat, err)
	}

	algorithm, err := g.encryptionAlgorithm(fields)
	if err != nil {
		return nil, err
	}

	if graphHasAgreement(fields.keyInfo) {
		return g.agreementEncryptedPlan(node, fields, algorithm, size)
	}

	if rsaOAEPAlgorithm(algorithm) {
		return g.rsaEncryptedPlan(node, fields, algorithm, size)
	}

	return g.wrappedEncryptedPlan(node, fields, algorithm, consumer, size, depth)
}

func (g *keyGraph) rsaEncryptedPlan(node graphNode, fields graphEncryptedFields, algorithm string, size int) (*graphKeyPlan, error) {
	binding, err := g.rsaMaterial(fields.keyInfo, algorithm)
	if err != nil {
		return nil, err
	}

	oaep, err := normalizeOAEP(g.options.Data.OAEP)
	if err != nil || oaep.Algorithm != algorithm {
		return nil, errors.Join(ErrPolicy, err)
	}

	public, ok := binding.Decrypter.Public().(*rsa.PublicKey)
	if !ok || validateRSAKey(public) != nil {
		return nil, ErrPolicy
	}

	if fields.method.Valid() {
		if err := checkEncryptionMethod(g.ctx, fields.method, algorithm, public.N.BitLen(), true); err != nil {
			return nil, err
		}

		if err := checkOAEP(g.ctx, fields.method, oaep); err != nil {
			return nil, err
		}
	}

	cipher, err := g.cipherPlan(node.document, fields.cipherData, public.Size())
	if err != nil {
		return nil, err
	}

	return &graphKeyPlan{algorithm: algorithm, keyBytes: size, provider: binding.Decrypter, oaep: oaep, cipher: cipher}, nil
}

func (g *keyGraph) wrappedEncryptedPlan(node graphNode, fields graphEncryptedFields, algorithm, consumer string, size, depth int) (*graphKeyPlan, error) {
	kekBytes := graphWrappingKeyBytes(algorithm)
	if kekBytes == 0 || algorithm == TripleDESKeyWrap && (!g.options.Data.AllowLegacy || fips140.Enabled() || consumer != TripleDESCBC && consumer != TripleDESKeyWrap) {
		return nil, ErrPolicy
	}

	if fields.method.Valid() {
		if err := checkEncryptionMethod(g.ctx, fields.method, algorithm, kekBytes*keyOctetBits, false); err != nil {
			return nil, err
		}
	}

	kek, err := g.consumerKey(node, fields.keyInfo, algorithm, kekBytes, depth)
	if err != nil {
		return nil, err
	}

	maximum := size + keyWrapBlockBytes
	if algorithm == TripleDESKeyWrap {
		maximum = tripleDESWrappedKeyBytes
	}

	cipher, err := g.cipherPlan(node.document, fields.cipherData, maximum)
	if err != nil {
		return nil, err
	}

	return &graphKeyPlan{algorithm: algorithm, keyBytes: size, sources: []*graphKeyPlan{kek}, cipher: cipher}, nil
}

func (g *keyGraph) encryptionAlgorithm(fields graphEncryptedFields) (string, error) {
	if fields.method.Valid() {
		algorithm := attributeValue(fields.method, lexicon.SecurityAttrAlgorithm)
		if _, exists := g.methods[algorithm]; !exists || algorithm == ConcatKDF {
			return "", ErrPolicy
		}

		return algorithm, nil
	}
	// Omitting EncryptionMethod requires an unambiguous application choice.
	names := []string{""}
	if fields.keyInfo.Valid() {
		names = nil

		for _, child := range fields.keyInfo.Children() {
			if child.Name() == elementName(SignatureNamespace, lexicon.DSigElementKeyName) {
				name, err := graphNameText(child)
				if err != nil {
					return "", err
				}

				names = append(names, name)
			}
		}
	}

	return g.algorithmForNames(names)
}

func (g *keyGraph) algorithmForNames(names []string) (string, error) {
	selected := ""

	for identity := range g.bindings {
		if !graphKeyAlgorithm(identity.algorithm) || identity.algorithm == ConcatKDF {
			continue
		}

		for _, name := range names {
			if identity.name != name {
				continue
			}

			if selected != "" && selected != identity.algorithm {
				return "", ErrPolicy
			}

			selected = identity.algorithm
		}
	}

	if selected != "" {
		return selected, nil
	}

	for algorithm := range g.methods {
		if algorithm == ConcatKDF {
			continue
		}

		if selected != "" {
			return "", ErrPolicy
		}

		selected = algorithm
	}

	if selected == "" {
		return "", errGraphKeyUnavailable
	}

	return selected, nil
}

func (g *keyGraph) rsaMaterial(info document.Element, algorithm string) (KeyGraphKey, error) {
	names := []string{""}

	if info.Valid() {
		if !graphAttributes(info, lexicon.SecurityAttrID) || len(info.Children()) == 0 || !graphStructuralText(info) {
			return KeyGraphKey{}, ErrFormat
		}

		names = nil

		for _, child := range info.Children() {
			if child.Name() != elementName(SignatureNamespace, lexicon.DSigElementKeyName) {
				return KeyGraphKey{}, ErrFormat
			}

			name, err := graphNameText(child)
			if err != nil {
				return KeyGraphKey{}, err
			}

			names = append(names, name)
		}
	}

	var (
		selected       KeyGraphKey
		selectedPublic *rsa.PublicKey
	)

	for _, name := range names {
		binding, ok := g.bindings[graphBinding{name, algorithm}]
		if !ok {
			continue
		}

		public, ok := binding.Decrypter.Public().(*rsa.PublicKey)
		if !ok || validateRSAKey(public) != nil {
			return KeyGraphKey{}, ErrPolicy
		}

		if selectedPublic != nil && (selectedPublic.E != public.E || selectedPublic.N.Cmp(public.N) != 0) {
			return KeyGraphKey{}, ErrPolicy
		}

		selected, selectedPublic = binding, public
	}

	if selectedPublic == nil {
		return KeyGraphKey{}, errGraphKeyUnavailable
	}

	return selected, nil
}

func (g *keyGraph) derivedPlan(node graphNode, size, depth int) (*graphKeyPlan, error) {
	// DerivedKey grammar positions select derivation parameters and
	// distinguish the derived-key label from the master-key lookup label.
	const (
		derivationMethodPosition     = 0
		derivedReferenceListPosition = 1
		derivedKeyNamePosition       = 2
		masterKeyNamePosition        = 3
	)

	if _, exists := g.methods[ConcatKDF]; g.options.ConcatKDF == nil || !exists || !sessionKeySize(size) || !graphAttributes(node.element(), lexicon.SecurityAttrID, lexicon.SecurityAttrType, attrRecipient) {
		return nil, ErrPolicy
	}

	method, master := document.Element{}, ""
	position := -1
	positions := map[document.Name]int{elementName(Namespace11, nameKeyDerivationMethod): derivationMethodPosition, elementName(Namespace, nameReferenceList): derivedReferenceListPosition, elementName(Namespace11, nameDerivedKeyName): derivedKeyNamePosition, elementName(Namespace11, nameMasterKeyName): masterKeyNamePosition}

	for _, raw := range node.node.Children {
		if raw.Kind == tree.TextNode && !xmlSpace(raw.Data) {
			return nil, ErrFormat
		}
	}

	for _, child := range node.element().Children() {
		index, known := positions[child.Name()]
		if !known || index <= position {
			return nil, ErrFormat
		}

		position = index
		switch index {
		case derivationMethodPosition:
			method = child
		case derivedReferenceListPosition:
			if _, err := graphReferences(child); err != nil {
				return nil, err
			}
		case derivedKeyNamePosition, masterKeyNamePosition:
			name, err := graphNameText(child)
			if err != nil {
				return nil, err
			}

			if index == masterKeyNamePosition {
				master = name
			}
		}
	}

	expected := *g.options.ConcatKDF
	if method.Valid() {
		actual, err := decodeConcatKDFParameters(g.ctx, method)
		if err != nil || !sameConcatKDFParameters(actual, expected) {
			return nil, errors.Join(ErrPolicy, err)
		}
	}

	key, err := g.namedMaterial(master, ConcatKDF, 0)
	if errors.Is(err, errGraphKeyUnavailable) {
		info := newElement(SignatureNamespace, lexicon.PrefixDSig, lexicon.DSigElementKeyInfo)
		name := newElement(SignatureNamespace, lexicon.PrefixDSig, lexicon.DSigElementKeyName)
		appendChild(name, &tree.Node{Kind: tree.TextNode, Data: master})
		appendChild(info, name)
		key, err = g.consumerKey(node, tree.Wrap(node.document.doc, info), ConcatKDF, g.options.MasterKeyBytes, depth+1)
	}

	if err != nil {
		return nil, err
	}

	return &graphKeyPlan{algorithm: ConcatKDF, sources: []*graphKeyPlan{key}, keyBytes: size, kdf: &expected}, nil
}

func (g *keyGraph) prepareKey(plan *graphKeyPlan, visited map[*graphKeyPlan]struct{}) error {
	if _, exists := visited[plan]; exists {
		return nil
	}

	visited[plan] = struct{}{}
	for _, source := range plan.sources {
		if err := g.prepareKey(source, visited); err != nil {
			return err
		}
	}

	if plan.cipher != nil {
		wrapped, err := g.readCipher(plan.cipher)
		if err != nil {
			return err
		}

		if len(wrapped) != plan.cipher.maximum {
			return ErrDecrypt
		}

		plan.wrapped = wrapped
	}

	return g.ctx.Err()
}

func (g *keyGraph) runKey(plan *graphKeyPlan) ([]byte, error) {
	if err := g.ctx.Err(); err != nil {
		return nil, err
	}

	if plan.done {
		return plan.value, nil
	}

	if plan.material != nil {
		plan.value, plan.done = plan.material, true
		return plan.value, nil
	}

	var input []byte

	for _, source := range plan.sources {
		value, err := g.runKey(source)
		if err != nil {
			return nil, err
		}

		if input == nil {
			input = value
		} else if subtle.ConstantTimeCompare(input, value) != 1 {
			return nil, ErrDecrypt
		}
	}

	var (
		value []byte
		err   error
	)

	switch {
	case plan.algorithm == "":
		value = input
	case plan.algorithm == ConcatKDF:
		value, err = DeriveConcatKey(g.ctx, input, plan.keyBytes*keyOctetBits, *plan.kdf)
	case rsaOAEPAlgorithm(plan.algorithm):
		parameters := &rsa.OAEPOptions{Hash: plan.oaep.Hash, MGFHash: plan.oaep.MGFHash, Label: bytes.Clone(plan.oaep.Label)}
		if provider, ok := plan.provider.(contextualDecrypter); ok {
			value, err = provider.decrypt(g.ctx, rand.Reader, plan.wrapped, parameters)
		} else {
			value, err = plan.provider.Decrypt(rand.Reader, plan.wrapped, parameters)
		}

		clear(parameters.Label)
	case plan.unwrap != nil:
		value, err = plan.unwrap(g.ctx, plan.wrapped)
	case plan.algorithm == TripleDESKeyWrap:
		block, blockErr := des.NewTripleDESCipher(input) // #nosec G405 -- Selected XMLENC legacy wrap, protected by explicit policy and FIPS gate.
		if blockErr != nil {
			return nil, ErrDecrypt
		}

		value, err = unwrapTripleDES(block, plan.wrapped)
	default:
		block, blockErr := aes.NewCipher(input)
		if blockErr != nil {
			return nil, ErrDecrypt
		}

		value, err = unwrapKey(block, plan.wrapped, plan.keyBytes)
	}

	if g.ctx.Err() != nil {
		clear(value)
		return nil, g.ctx.Err()
	}

	if err != nil || len(value) != plan.keyBytes {
		clear(value)

		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		return nil, ErrDecrypt
	}

	plan.value, plan.done = value, true

	return value, nil
}

func (g *keyGraph) retrievedKey(doc *graphDocument, method document.Element) (graphNode, error) {
	if !graphAttributes(method, lexicon.SecurityAttrURI, lexicon.SecurityAttrType) || len(method.Children()) != 0 || !xmlSpace(method.Text()) {
		return graphNode{}, ErrFormat
	}

	uri, exists := method.Attribute(document.Name{Local: lexicon.SecurityAttrURI})
	if !exists {
		uri = ""
	}

	target, err := g.referenceTarget(doc, method, uri)
	if err != nil {
		return graphNode{}, err
	}

	typ := graphRetrievalType(target.node.Name)
	if typ == "" || attributeValue(method, lexicon.SecurityAttrType) != "" && attributeValue(method, lexicon.SecurityAttrType) != typ {
		return graphNode{}, ErrFormat
	}

	return target, nil
}

func (g *keyGraph) referenceListMatches(key, target graphNode) (bool, error) {
	var list document.Element

	for _, child := range key.element().Children() {
		if child.Name() == elementName(Namespace, nameReferenceList) {
			if list.Valid() {
				return false, ErrFormat
			}

			list = child
		}
	}

	if !list.Valid() {
		return false, nil
	}

	refs, err := graphReferences(list)
	if err != nil {
		return false, err
	}

	wanted := elementName(Namespace, nameDataReference)
	if graphRetrievalType(target.node.Name) != "" {
		wanted = elementName(Namespace, nameKeyReference)
	}

	for _, ref := range refs {
		if err := g.charge(1, 0); err != nil {
			return false, err
		}

		if ref.Name() != wanted {
			continue
		}

		matched, err := g.referenceMatches(key.document, ref, target, attributeValue(ref, lexicon.SecurityAttrURI))
		if err != nil {
			return false, err
		}

		if matched {
			return true, nil
		}
	}

	return false, nil
}

func (g *keyGraph) referenceMatches(source *graphDocument, element document.Element, target graphNode, raw string) (bool, error) {
	if raw == "" || strings.HasPrefix(raw, "#") {
		if source != target.document {
			return false, nil
		}

		candidate, err := g.localTarget(source, raw)

		return candidate == target, err
	}

	base, err := g.absoluteReference(source, element, raw)
	if err != nil {
		return false, err
	}

	fragment := base.EscapedFragment()

	base.Fragment, base.RawFragment = "", ""
	if base.String() != target.document.uri {
		return false, nil
	}

	uri := ""
	if fragment != "" {
		uri = "#" + fragment
	}

	candidate, err := g.localTarget(target.document, uri)

	return candidate == target, err
}

type graphSources struct {
	graph     *keyGraph
	target    graphNode
	algorithm string
	size      int
	depth     int
	plans     []*graphKeyPlan
}

func (b *graphSources) add(plan *graphKeyPlan, err error) error {
	if errors.Is(err, errGraphKeyUnavailable) {
		return nil
	}

	if err != nil {
		return err
	}

	b.plans = append(b.plans, plan)

	return nil
}

func (b *graphSources) keyInfo(info document.Element) error {
	g := b.graph
	if !info.Valid() {
		return b.add(g.namedMaterial("", b.algorithm, b.size))
	}

	if !graphAttributes(info, lexicon.SecurityAttrID) || len(info.Children()) == 0 || !graphStructuralText(info) {
		return ErrFormat
	}

	for _, child := range info.Children() {
		switch child.Name() {
		case elementName(SignatureNamespace, lexicon.DSigElementKeyName):
			name, err := graphNameText(child)
			if err != nil {
				return err
			}

			if err := b.named(name); err != nil {
				return err
			}
		case elementName(Namespace, nameEncryptedKey), elementName(Namespace11, nameDerivedKey):
			_, raw := tree.Unwrap(child)
			if err := b.add(g.keyPlan(graphNode{b.target.document, raw}, b.algorithm, b.size, b.depth+1)); err != nil {
				return err
			}
		case elementName(SignatureNamespace, lexicon.DSigElementRetrievalMethod):
			candidate, err := g.retrievedKey(b.target.document, child)
			if err != nil {
				return err
			}

			if err := b.add(g.keyPlan(candidate, b.algorithm, b.size, b.depth+1)); err != nil {
				return err
			}
		default:
			return ErrFormat
		}
	}

	return nil
}

func (b *graphSources) named(name string) error {
	g := b.graph
	if err := b.add(g.namedMaterial(name, b.algorithm, b.size)); err != nil {
		return err
	}

	for _, doc := range g.ordered {
		for _, candidate := range doc.keys {
			if err := g.charge(1, 0); err != nil {
				return err
			}

			carried, present, err := g.keyName(candidate)
			if err != nil {
				return err
			}

			if !present || carried != name {
				continue
			}

			if err := b.add(g.keyPlan(candidate, b.algorithm, b.size, b.depth+1)); err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *graphSources) references() error {
	g := b.graph
	for _, doc := range g.ordered {
		for _, candidate := range doc.keys {
			if err := g.charge(1, 0); err != nil {
				return err
			}

			if candidate == b.target {
				continue
			}

			matched, err := g.referenceListMatches(candidate, b.target)
			if err != nil {
				return err
			}

			if matched {
				if err := b.add(g.keyPlan(candidate, b.algorithm, b.size, b.depth+1)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func graphRetrievalType(name document.Name) string {
	if name == elementName(Namespace, nameEncryptedKey) {
		return Namespace + nameEncryptedKey
	}

	if name == elementName(Namespace11, nameDerivedKey) {
		return Namespace11 + nameDerivedKey
	}

	return ""
}

func graphHasAttribute(element document.Element, name string) bool {
	_, exists := element.Attribute(document.Name{Local: name})
	return exists
}
