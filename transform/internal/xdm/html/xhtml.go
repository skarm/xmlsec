// Derived in part from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt.

package html

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// XHTMLIsElement recognizes XHTML elements and the HTML5 null-namespace form.
func XHTMLIsElement(uri, local string, html5 bool) bool {
	return uri == lexicon.NamespaceXHTML || html5 && uri == "" && html5ElementName(strings.ToLower(local))
}

func html5ElementName(local string) bool {
	if lookupElement(local) != nil {
		return true
	}

	switch local {
	case "article", "aside", "audio", "bdi", "canvas", "command", elemData, "datalist", "details", "dialog", elemEmbed, "figcaption", "figure", "footer", "header", "hgroup", elemKeygen, "main", "mark", "math", "menuitem", "meter", "nav", "output", "picture", "progress", "rb", "rp", "rt", "rtc", "ruby", "section", "slot", elemSource, "summary", "svg", "template", "time", elemTrack, elemVideo, elemWbr:
		return true
	}

	return false
}

func xhtmlInline(local string) bool {
	if descriptor := lookupElement(local); descriptor != nil && descriptor.inline != 0 {
		return true
	}

	switch local {
	case "audio", "bdi", "canvas", elemData, "datalist", elemEmbed, elemKeygen, "mark", "math", "meter", "output", "picture", "progress", "rb", "rp", "rt", "rtc", "ruby", "svg", "template", "time", elemVideo, elemWbr:
		return true
	}

	return false
}

// ConfigureXHTML applies name-aware rules before markup generation. URI values
// bypass maps and requested normalization; they always use NFC URI escaping.
func ConfigureXHTML(options *tree.XMLWriteOptions, html5, escapeURI bool) {
	options.EmptyElement = func(name tree.Name) tree.EmptyElementMode {
		if XHTMLIsElement(name.Space, name.Local, html5) && xhtmlEmpty(strings.ToLower(name.Local), html5) {
			return tree.EmptyElementSpaced
		}

		return tree.EmptyElementExpanded
	}
	if escapeURI {
		options.AttributeWriter = func(ctx context.Context, out io.Writer, element tree.Name, attribute tree.Attribute) (bool, error) {
			if attribute.Name.Space != "" || !XHTMLIsElement(element.Space, element.Local, html5) || !isURIAttr(strings.ToLower(attribute.Name.Local), strings.ToLower(element.Local)) {
				return false, nil
			}

			return true, writeURIAttribute(ctx, out, attribute.Value)
		}
	}

	options.InlineElement = func(name tree.Name) bool {
		return XHTMLIsElement(name.Space, name.Local, html5) && xhtmlInline(strings.ToLower(name.Local))
	}
	options.PreserveContent = func(name tree.Name) bool {
		if !XHTMLIsElement(name.Space, name.Local, html5) {
			return false
		}

		local := strings.ToLower(name.Local)

		return xhtmlInline(local) || local == "pre" || local == "script" || local == "style" || local == "title" || local == "textarea"
	}
}

func xhtmlEmpty(local string, html5 bool) bool {
	switch local {
	case "area", "base", "br", "col", elemEmbed, "hr", "img", elemInput, "link", "meta", "param":
		return true
	case elemKeygen, elemSource, elemTrack, elemWbr:
		return html5
	case "basefont", "frame", "isindex":
		return !html5
	}

	return false
}

// PrepareXHTML mutates only an owned serialization copy. Metadata replacement
// visits every recognized head, including a selected head or a nested one.
func PrepareXHTML(ctx context.Context, doc *xdm.Document, html5 bool, contentType string) error {
	if html5 {
		normalizeXHTML5Prefixes(doc)
	} else {
		normalizeXHTMLNamespace(doc)
	}

	if contentType == "" {
		return nil
	}

	var heads []*xdm.Element

	if err := xdm.Walk(doc, xdm.NodeWalkerFunc(func(node xdm.Node) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if element, ok := node.(*xdm.Element); ok && XHTMLIsElement(element.URI(), element.LocalName(), html5) && strings.EqualFold(element.LocalName(), "head") {
			heads = append(heads, element)
		}

		return nil
	})); err != nil {
		return err
	}

	for _, head := range heads {
		if err := replaceXHTMLMetadata(doc, head, html5, contentType); err != nil {
			return err
		}
	}

	return nil
}

func replaceXHTMLMetadata(doc *xdm.Document, head *xdm.Element, html5 bool, contentType string) error {
	var children []xdm.Node

	for child := head.FirstChild(); child != nil; {
		next := child.NextSibling()

		mutable, ok := child.(xdm.MutableNode)
		if !ok {
			return fmt.Errorf("unsupported XHTML serialization child %T", child)
		}

		xdm.UnlinkNode(mutable)

		meta, ok := child.(*xdm.Element)
		if !ok || !XHTMLIsElement(meta.URI(), meta.LocalName(), html5) || !strings.EqualFold(meta.LocalName(), "meta") || !isContentTypeMeta(meta) {
			children = append(children, child)
		}

		child = next
	}

	meta, err := doc.CreateElementNS("meta", xdm.NewNamespace(head.Prefix(), head.URI()))
	if err != nil {
		return err
	}

	if err = meta.SetAttribute("http-equiv", "Content-Type"); err != nil {
		return err
	}

	if err = meta.SetAttribute("content", contentType); err != nil {
		return err
	}

	if err = head.AddChild(meta); err != nil {
		return err
	}

	for _, child := range children {
		if err = head.AddChild(child); err != nil {
			return err
		}
	}

	return nil
}

// normalizeXHTMLNamespace walks the document and converts prefixed XHTML
// namespace elements to use the default namespace (unprefixed), as required
// by the XHTML output method. The default namespace declaration is added
// only to the root element; descendants inherit it.
func normalizeXHTMLNamespace(doc *xdm.Document) {
	normalizer := xhtmlNamespaceNormalizer{}
	// The freshly built tree is acyclic; namespace normalization cannot create cycles.
	_ = xdm.Walk(doc, xdm.NodeWalkerFunc(normalizer.visit))
}

// Serialization 3.1 section 6 removes bindings for all three namespaces from
// every element, except prefixes used by attributes on that element or an
// ancestor. Element names in these namespaces use a new default binding.
func normalizeXHTML5Prefixes(doc *xdm.Document) {
	_ = xdm.Walk(doc, xdm.NodeWalkerFunc(func(n xdm.Node) error {
		elem, ok := n.(*xdm.Element)
		if !ok {
			return nil
		}

		for _, ns := range elem.Namespaces() {
			if xhtml5Namespace(ns.URI()) && !ancestorAttributeUsesPrefix(elem, ns.Prefix()) {
				elem.RemoveNamespaceByPrefix(ns.Prefix())
			}
		}

		if uri := elem.URI(); xhtml5Namespace(uri) {
			_ = elem.DeclareNamespace("", uri)
			_ = elem.SetActiveNamespace("", uri)
		}

		return nil
	}))
}

func xhtml5Namespace(uri string) bool {
	return uri == lexicon.NamespaceXHTML || uri == lexicon.NamespaceSVG || uri == lexicon.NamespaceMathML
}

func ancestorAttributeUsesPrefix(elem *xdm.Element, prefix string) bool {
	if prefix == "" {
		return false
	}

	for node := xdm.Node(elem); node != nil; node = node.Parent() {
		if parent, ok := node.(*xdm.Element); ok {
			for _, attr := range parent.Attributes() {
				if attr.Prefix() == prefix {
					return true
				}
			}
		}
	}

	return false
}

type xhtmlNamespaceNormalizer struct {
	sharedNS *xdm.Namespace
	rootDone bool
}

func (c *xhtmlNamespaceNormalizer) visit(n xdm.Node) error {
	elem, ok := n.(*xdm.Element)
	if !ok {
		return nil
	}

	if elem.URI() != lexicon.NamespaceXHTML {
		return nil
	}

	if elem.Prefix() == "" {
		// Already using default namespace. Capture the NS node if we
		// haven't seen one yet.
		if c.sharedNS == nil {
			for _, ns := range elem.Namespaces() {
				if ns.Prefix() == "" && ns.URI() == lexicon.NamespaceXHTML {
					c.sharedNS = ns
					break
				}
			}
		}

		return nil
	}

	oldPrefix := elem.Prefix()
	elem.RemoveNamespaceByPrefix(oldPrefix)

	if !c.rootDone {
		// First prefixed element: declare default XHTML namespace here
		_ = elem.DeclareNamespace("", lexicon.NamespaceXHTML)
		for _, ns := range elem.Namespaces() {
			if ns.Prefix() == "" && ns.URI() == lexicon.NamespaceXHTML {
				c.sharedNS = ns
				break
			}
		}

		c.rootDone = true
	}

	if c.sharedNS != nil {
		elem.SetNamespace(c.sharedNS)
	}

	return nil
}
