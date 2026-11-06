package protocol

import (
	"context"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/saml/binding"
	"github.com/skarm/xmlsec/saml/internal/xmlsig"
	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

// SignSOAP replaces a message's direct signature in its final SOAP namespace
// context and returns the envelope. Use this for Inclusive C14N as well as
// Exclusive C14N. Embedded messages/assertions retain their own signatures and
// must already be valid in that context. Headers are copied, never authenticated
// by the SAML body signature. ECP validates its routing headers separately.
func SignSOAP(ctx context.Context, message *document.Document, key SigningKey, headers ...document.Element) (*document.Document, error) {
	envelope, err := binding.WrapSOAP(ctx, message, headers...)
	if err != nil {
		return nil, err
	}

	private, err := tree.Clone(ctx, envelope)
	if err != nil {
		return nil, err
	}

	root := tree.Root(private)
	body := root.Children[len(root.Children)-1]
	target := body.Children[0]

	if len(key.InclusivePrefixes) > 0 || hasInclusiveNamespaces(message.Root()) {
		key = namespaceSigningKey(message.Root(), key)
	}

	children := make([]*tree.Node, 0, len(target.Children))
	for _, child := range target.Children {
		if child.Kind == tree.ElementNode && child.Name == xmlutil.Name(xmlutil.DS, lexicon.DSigElementSignature) {
			continue
		}

		children = append(children, child)
	}

	target.Children = children

	d, err := tree.Reparse(ctx, private, document.DefaultLimits())
	if err != nil {
		return nil, err
	}

	element := d.Root().Children()[len(d.Root().Children())-1].Children()[0]

	k, err := signing(key)
	if err != nil {
		return nil, err
	}

	d, err = xmlsig.Sign(ctx, d, element, k, true)
	if err != nil {
		return nil, err
	}

	return d, nil
}
