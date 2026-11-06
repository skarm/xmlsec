package protocol

import (
	"context"
	"io"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

func attributeBudget(ctx context.Context, a document.Element, l Limits) error {
	if len(a.Children()) > l.MaxValuesPerAttribute {
		return ErrProfile
	}

	for _, v := range a.Children() {
		if err := c14n.WriteElement(ctx, io.Discard, v, c14n.Options{Algorithm: c14n.ExclusiveWithComments, InclusivePrefixes: valuePrefixes(v), MaxOutputBytes: l.MaxValueBytes}); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func authorityAttributeBudget(ctx context.Context, d *document.Document, l Limits) error {
	total := 0

	for _, s := range d.Root().Children() {
		if s.Name() != xmlutil.Name(AssertionNamespace, xmlNameAttributeStatement) {
			continue
		}

		total += len(s.Children())
		if total > l.MaxAttributes {
			return ErrProfile
		}

		for _, a := range s.Children() {
			if err := attributeBudget(ctx, a, l); err != nil {
				return err
			}
		}
	}

	return nil
}
