package xades

import (
	"context"

	"github.com/skarm/xmlsec/internal/lexicon"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/xmldsig"
)

// CountersignedSignatureType identifies the EN319132-1 5.2.7 Reference whose
// complete target is another signature's ds:SignatureValue element.
const CountersignedSignatureType = countersignedSignatureType

// CounterSignatures returns unverified enclosed signatures. The enclosing
// signature does not authenticate this unsigned property. Verify each child
// with an explicit key/certificate, then call VerifyCounterSignature.
func (r *BaselineResult) CounterSignatures() []document.Element {
	if r == nil {
		return nil
	}

	var out []document.Element

	for _, property := range r.UnsignedSignatureProperties() {
		if property.Name() != name("CounterSignature") {
			continue
		}

		out = append(out, property.Children()...)
	}

	return out
}

// VerifyCounterSignature binds a separately authenticated child result to the
// complete SignatureValue of enclosing, including its XML tags. It does not
// infer child-key trust or validate claimed time, PKIX or third-party authority.
func VerifyCounterSignature(ctx context.Context, enclosing *BasicResult, counter *xmldsig.SignatureResult) error {
	if ctx == nil || enclosing == nil || enclosing.Signature() == nil || counter == nil {
		return ErrProfile
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	parent := enclosing.Signature().Signature()
	child := counter.Signature()
	owner, node := tree.Unwrap(child)

	parentOwner, _ := tree.Unwrap(parent)
	if owner != parentOwner || node == nil || node.Parent == nil || node.Parent.Name != name("CounterSignature") {
		return ErrProfile
	}

	container := tree.Wrap(owner, node.Parent)
	if err := checkCounterContainer(container); err != nil {
		return err
	}

	usp := node.Parent.Parent
	if usp == nil || usp.Name != name("UnsignedSignatureProperties") {
		return ErrProfile
	}

	unsigned := usp.Parent
	if unsigned == nil || unsigned.Name != name("UnsignedProperties") {
		return ErrProfile
	}

	qp := unsigned.Parent
	if qp == nil || qp.Name != name("QualifyingProperties") {
		return ErrProfile
	}

	object := qp.Parent
	if object == nil || object.Name != ds("Object") || object.Parent == nil || !tree.Wrap(owner, object.Parent).Same(parent) {
		return ErrProfile
	}

	target, err := childNamed(parent, ds(lexicon.DSigElementSignatureValue))
	if err != nil {
		return err
	}

	if err := checkBaselineCounterReferences(counter); err != nil {
		return err
	}

	for _, ref := range counter.References() {
		if ref.Target().Same(target) && ref.CoversElement(target) {
			return nil
		}
	}

	return ErrProfile
}

func checkCounterContainer(element document.Element) error {
	if baselineAttrs(element, nil, "Id") != nil {
		return ErrProfile
	}

	_, err := children(element, ds(lexicon.DSigElementSignature))

	return err
}

func checkBaselineCounterReferences(signature *xmldsig.SignatureResult) error {
	for _, ref := range signature.References() {
		if ref.Type() != countersignedSignatureType {
			continue
		}

		target := ref.Target()

		_, node := tree.Unwrap(target)
		if target.Name() != ds(lexicon.DSigElementSignatureValue) || node.Parent == nil || node.Parent.Name != ds(lexicon.DSigElementSignature) || !ref.CoversElement(target) {
			return ErrProfile
		}
	}

	return nil
}
