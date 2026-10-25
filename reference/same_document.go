package reference

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// SameDocumentResolver indexes explicitly typed IDs in one immutable snapshot.
// IDs must be unique NCNames. Resolve supports concurrent calls; it performs no
// schema-based typing or XPath evaluation.
type SameDocumentResolver struct {
	doc *document.Document
	ids map[string]document.Element
}

// NewSameDocumentResolver indexes the explicit application ID attribute and rejects
// duplicate identifiers.
func NewSameDocumentResolver(ctx context.Context, doc *document.Document, idAttribute document.Name) (*SameDocumentResolver, error) {
	if idAttribute == (document.Name{}) {
		idAttribute.Local = "ID"
	}

	return NewSameDocumentResolverWithRules(ctx, doc, []IDAttributeRule{{Attribute: idAttribute}})
}

// NewSameDocumentResolverWithRules indexes the union of explicit rules. Rules
// are consumed during construction and are not retained. Empty rules are valid
// (only whole-document URIs can then resolve). At most 32 rules with 64 element
// QNames each are accepted. ID collisions are rejected across all namespaces.
func NewSameDocumentResolverWithRules(ctx context.Context, doc *document.Document, rules []IDAttributeRule) (*SameDocumentResolver, error) {
	if ctx == nil || doc == nil || !doc.Root().Valid() {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if len(rules) > 32 {
		return nil, fmt.Errorf("%w: too many ID rules", ErrPolicy)
	}

	if err := validateSameDocumentRules(rules); err != nil {
		return nil, err
	}

	r := &SameDocumentResolver{doc: doc, ids: make(map[string]document.Element)}

	if err := r.indexIDNodes(ctx, tree.Root(doc), rules); err != nil {
		return nil, err
	}

	return r, nil
}

func validateSameDocumentRules(rules []IDAttributeRule) error {
	for _, rule := range rules {
		if !tree.NCName(rule.Attribute.Local) || rule.Attribute.Space == tree.XMLNSNamespace || len(rule.Elements) > 64 {
			return fmt.Errorf("%w: ID rule", ErrPolicy)
		}

		for _, name := range rule.Elements {
			if !tree.NCName(name.Local) || name.Space == tree.XMLNSNamespace {
				return fmt.Errorf("%w: ID element QName", ErrPolicy)
			}
		}
	}

	return nil
}

// Target resolves a same-document URI without materializing any NodeSet. The
// boolean denotes the document node (not the root element). No trust is implied.
func (r *SameDocumentResolver) Target(ctx context.Context, uri string) (document.Element, bool, error) {
	m, err := r.identify(ctx, uri)
	if err != nil {
		return document.Element{}, false, err
	}

	return m.target, m.whole, nil
}

// Resolve selects the authorized same-document target and applies URI-specific comment rules.
func (r *SameDocumentResolver) Resolve(ctx context.Context, uri string) (Resolved, error) {
	result, err := r.identify(ctx, uri)
	if err != nil {
		return Resolved{}, err
	}

	var set document.NodeSet
	if result.whole {
		set, err = r.doc.AllNodes(ctx)
	} else {
		set, err = result.target.Subtree(ctx)
	}

	if err != nil {
		return Resolved{}, err
	}

	if !result.comments {
		set, err = tree.FilterNodeSet(ctx, set, func(n document.Node) bool { return n.Kind() != document.CommentNode })
		if err != nil {
			return Resolved{}, err
		}
	}

	result.data, _ = Nodes(set)

	return result, nil
}

// Resolve implements URI="", #ID, #xpointer(/), #xpointer(id('ID')) and the
// double-quoted id form. Percent escapes are decoded ONCE in the fragment.
// Other XPointer expressions, whitespace variants and external URIs fail closed.
func (r *SameDocumentResolver) identify(ctx context.Context, uri string) (Resolved, error) {
	if ctx == nil || r == nil || r.doc == nil {
		return Resolved{}, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return Resolved{}, err
	}

	result := Resolved{uri: uri}
	id := ""

	switch {
	case uri == "":
		result.whole = true
	case strings.HasPrefix(uri, "#"):
		fragment, err := url.PathUnescape(uri[1:])
		if err != nil || !utf8.ValidString(fragment) {
			return Resolved{}, fmt.Errorf("%w: malformed fragment", ErrInput)
		}

		switch {
		case tree.NCName(fragment):
			id = fragment
		case fragment == "xpointer(/)":
			result.whole = true
			result.comments = true
		case strings.HasPrefix(fragment, "xpointer(id(") && strings.HasSuffix(fragment, "))"):
			value := fragment[len("xpointer(id(") : len(fragment)-2]
			if len(value) < 3 || value[0] != '\'' && value[0] != '"' || value[len(value)-1] != value[0] || !tree.NCName(value[1:len(value)-1]) {
				return Resolved{}, fmt.Errorf("%w: XPointer id form", ErrUnsupported)
			}

			id = value[1 : len(value)-1]
			result.comments = true
		default:
			return Resolved{}, fmt.Errorf("%w: fragment expression", ErrUnsupported)
		}
	default:
		return Resolved{}, fmt.Errorf("%w: not a same-document reference", ErrUnsupported)
	}

	if !result.whole {
		target, ok := r.ids[id]
		if !ok {
			return Resolved{}, fmt.Errorf("%w: unresolved ID %q", ErrInput, id)
		}

		result.target = target
	}

	return result, nil
}

func (r *SameDocumentResolver) indexIDNodes(ctx context.Context, n *tree.Node, rules []IDAttributeRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	found := false

	if n.Kind == tree.ElementNode {
		for _, a := range n.Attrs {
			if !matchesIDRule(rules, a.Name, n.Name) {
				continue
			}

			if found {
				return fmt.Errorf("%w: multiple ID attributes on one element", ErrInput)
			}

			found = true

			if !tree.NCName(a.Value) {
				return fmt.Errorf("%w: ID is not an NCName", ErrInput)
			}

			if _, ok := r.ids[a.Value]; ok {
				return fmt.Errorf("%w: duplicate ID %q", ErrInput, a.Value)
			}

			r.ids[a.Value] = tree.Wrap(r.doc, n)
		}
	}

	for _, child := range n.Children {
		if err := r.indexIDNodes(ctx, child, rules); err != nil {
			return err
		}
	}

	return nil
}

func matchesIDRule(rules []IDAttributeRule, a, e document.Name) bool {
	for _, rule := range rules {
		if rule.Attribute != a {
			continue
		}

		if len(rule.Elements) == 0 {
			return true
		}

		if slices.Contains(rule.Elements, e) {
			return true
		}
	}

	return false
}

// IDAttributeRule treats an exact attribute name as an ID on selected element
// names. Empty Elements applies the rule to every element. Repeating a rule for
// the same attribute is allowed; two distinct ID attributes on one element are
// rejected even if their values agree. ID typing does not use local-name guesses,
// automatic xml:id recognition, schemas or DTD declarations.
type IDAttributeRule struct {
	// Attribute is the exact expanded name of the attribute to treat as an ID.
	Attribute document.Name
	// Elements restricts the rule to exact expanded names. Empty applies it to all elements.
	Elements []document.Name
}

// Resolved retains an immutable same-document target and its comment-selection rules.
type Resolved struct {
	data     Data
	target   document.Element
	uri      string
	whole    bool
	comments bool
}

// Data returns the immutable resolved transform input.
func (r Resolved) Data() Data { return r.data }

// Target is invalid for a whole-document reference (document node != root element).
func (r Resolved) Target() document.Element { return r.target }

// URI returns the reference URI.
func (r Resolved) URI() string { return r.uri }

// WholeDocument returns whether the URI selects the entire document.
func (r Resolved) WholeDocument() bool { return r.whole }

// RetainsComments returns whether URI resolution retains comment nodes.
func (r Resolved) RetainsComments() bool { return r.comments }
