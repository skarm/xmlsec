package tree

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
)

// RecordOptions selects disjoint XML subtrees and bounds each record
// independently of the total stream length.
type RecordOptions struct {
	// Path is a nonempty, exact expanded-name path beginning at the document root.
	Path []Name
	// Limits bounds each record. MaxBytes counts normalized UTF-8 bytes per record
	// and bounds individual lexical tokens outside records. MaxDepth also bounds
	// enclosing elements. Zero selects DefaultLimits.
	Limits Limits
	// MaxInputBytes bounds the complete stream before and after decoding.
	// Zero permits arbitrary total length.
	MaxInputBytes int64
	// MaxRecords bounds emitted records; zero permits arbitrary record count.
	MaxRecords int
}

// ReadRecords validates an XML stream and emits independent immutable record
// snapshots. Memory is bounded by one record/token plus ancestor metadata;
// retaining snapshots in emit is the caller's choice. Earlier callbacks and
// their output are not rolled back if a later record or the enclosing XML fails.
// src remains caller-owned. Namespaces and inherited xml:* context are preserved.
func ReadRecords(ctx context.Context, src io.Reader, options RecordOptions, emit func(*Document) error) error {
	return (ParseOptions{}).ReadRecords(ctx, src, options, emit)
}

// ReadRecords applies the parser policy; per-record limits come from options.
func (o ParseOptions) ReadRecords(ctx context.Context, src io.Reader, options RecordOptions, emit func(*Document) error) error {
	if ctx == nil || nilcheck.IsNil(src) || emit == nil || len(options.Path) == 0 {
		return ErrMalformed
	}

	limits := options.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}

	if err := limits.Validate(); err != nil {
		return err
	}

	if options.MaxInputBytes < 0 || options.MaxRecords < 0 || len(options.Path) > limits.MaxDepth {
		return ErrLimit
	}

	for _, name := range options.Path {
		if !NCName(name.Local) {
			return ErrMalformed
		}
	}

	maximum := options.MaxInputBytes
	if maximum == 0 {
		maximum = math.MaxInt64
	}

	input, err := newXMLInput(ctx, src, maximum, limits.MaxBytes)
	if err != nil {
		return err
	}

	p := readerParser(input, limits)
	p.relativeNamespaces = o.AllowRelativeNamespaces
	p.singleByteEncodings = o.AllowSingleByteEncodings
	records := recordState{parser: &p, options: options, emit: emit}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		offset := p.decoder.InputOffset()

		input.outside = len(p.stack) == 0

		token, err := p.decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("%w: %w", ErrMalformed, err)
		}

		if err := records.token(token, offset); err != nil {
			return err
		}
	}

	if p.doc.root == nil || len(p.stack) != 0 {
		return fmt.Errorf("%w: missing or unclosed root", ErrMalformed)
	}

	if p.encoding.name != nameUTF8 && !p.encoding.bom && !p.seenDecl {
		return ErrMalformed
	}

	return ctx.Err()
}

type recordState struct {
	parser   *documentParser
	options  RecordOptions
	emit     func(*Document) error
	selected *Node
	start    int64
	count    int
}

func (r *recordState) token(token xml.Token, offset int64) error {
	p := r.parser
	if _, text := token.(xml.CharData); !text {
		if err := p.flushText(); err != nil {
			return err
		}
	}

	if err := p.consumeToken(token, offset); err != nil {
		return err
	}

	if _, start := token.(xml.StartElement); start && r.selected == nil && r.matches() {
		r.selected = p.stack[len(p.stack)-1].node
		r.start = offset
		p.count = 1
	}

	if r.selected != nil {
		size := p.decoder.InputOffset() - r.start
		if size > int64(p.doc.limits.MaxBytes) {
			return ErrLimit
		}

		if _, end := token.(xml.EndElement); end && len(p.stack) == len(r.options.Path)-1 {
			if r.options.MaxRecords > 0 && r.count >= r.options.MaxRecords {
				return ErrLimit
			}

			node := r.selected

			node.NS = inheritedRecordNamespaces(node)
			if err := inheritRecordAttributes(node); err != nil {
				return err
			}

			if len(node.Attrs)+len(node.NS) > p.doc.limits.MaxAttributesPerElement || len(node.NS)+1 > p.doc.limits.namespaceLimit() {
				return ErrLimit
			}

			node.Parent = nil
			doc := &Document{root: node, children: []*Node{node}, limits: p.doc.limits, inputBytes: int(size)}

			r.count++
			if err := r.emit(doc); err != nil {
				return err
			}

			r.selected = nil
		}
	}

	if r.selected == nil {
		p.pendingText.Reset()
		p.count = 0

		p.doc.children = nil
		for _, frame := range p.stack {
			frame.node.Children = nil
		}
	}

	return nil
}

func inheritedRecordNamespaces(node *Node) []Namespace {
	scope := namespaceScope(node)

	prefixes := make([]string, 0, len(scope))
	for prefix := range scope {
		if prefix != lexicon.PrefixXML {
			prefixes = append(prefixes, prefix)
		}
	}

	slices.Sort(prefixes)

	out := make([]Namespace, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, Namespace{Prefix: prefix, URI: scope[prefix]})
	}

	return out
}

func inheritRecordAttributes(node *Node) error {
	seen := make(map[Name]bool)
	for _, attr := range node.Attrs {
		seen[attr.Name] = true
	}

	for ancestor := node.Parent; ancestor != nil; ancestor = ancestor.Parent {
		for _, attr := range ancestor.Attrs {
			if attr.Name.Space == XMLNamespace && (attr.Name.Local == "lang" || attr.Name.Local == xmlSpaceName) && !seen[attr.Name] {
				node.Attrs = append(node.Attrs, attr)
				seen[attr.Name] = true
			}
		}
	}
	// Resolve the inherited base chain before detaching the record.
	base, err := recordBaseURI(node)
	if err != nil {
		return err
	}

	if base != "" {
		name := Name{Space: XMLNamespace, Local: lexicon.AttrBase}
		for i := range node.Attrs {
			if node.Attrs[i].Name == name {
				node.Attrs[i].Value = base
				return nil
			}
		}

		node.Attrs = append(node.Attrs, Attribute{Name: name, Prefix: lexicon.PrefixXML, Value: base})
	}

	return nil
}

func recordBaseURI(node *Node) (string, error) {
	var ancestors []*Node
	for n := node; n != nil; n = n.Parent {
		ancestors = append(ancestors, n)
	}

	base := ""

	for _, n := range slices.Backward(ancestors) {
		for _, attr := range n.Attrs {
			if attr.Name == (Name{Space: XMLNamespace, Local: lexicon.AttrBase}) {
				resolved, err := joinURIReferences(base, attr.Value)
				if err != nil {
					return "", err
				}

				base = resolved
			}
		}
	}

	return base, nil
}

func (r *recordState) matches() bool {
	stack := r.parser.stack
	if len(stack) != len(r.options.Path) {
		return false
	}

	for i, frame := range stack {
		if frame.node.Name != r.options.Path[i] {
			return false
		}
	}

	return true
}
