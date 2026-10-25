package xmlutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/internal/xmltime"
)

// Assertion identifies the Assertion algorithm or protocol URI.
const Assertion = lexicon.NamespaceSAMLAssertion

// Protocol is the SAML 2.0 protocol namespace URI.
const Protocol = lexicon.NamespaceSAMLProtocol

// Metadata identifies the Metadata algorithm or protocol URI.
const Metadata = lexicon.NamespaceSAMLMetadata

// DS identifies the DS algorithm or protocol URI.
const DS = lexicon.NamespaceDSig

// ErrSchema reports unsupported or invalid SAML structure.
var ErrSchema = errors.New("unsupported or invalid SAML structure")

// NewID generates an unpredictable SAML ID using crypto/rand.
func NewID() (string, error) {
	var b [20]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}

	return "_" + hex.EncodeToString(b[:]), nil
}

// Name constructs an expanded XML name.
func Name(ns, local string) document.Name { return document.Name{Space: ns, Local: local} }

// Attr returns an unqualified attribute value, or an empty string when absent.
func Attr(e document.Element, n string) string {
	s, _ := e.Attribute(document.Name{Local: n})
	return s
}

// Attrs requires the listed attributes and rejects undeclared attributes.
func Attrs(e document.Element, required, optional []string) error {
	seen := make(map[string]bool)

	for _, a := range e.Attributes() {
		if a.Name.Space != "" {
			return ErrSchema
		}

		ok := slices.Contains(required, a.Name.Local) || slices.Contains(optional, a.Name.Local)
		if !ok {
			return ErrSchema
		}

		seen[a.Name.Local] = true
	}

	for _, n := range required {
		if !seen[n] {
			return ErrSchema
		}
	}

	return nil
}

// Space reports whether s contains only XML whitespace.
func Space(s string) bool {
	for _, r := range s {
		if r != ' ' && r != '\r' && r != '\n' && r != '\t' {
			return false
		}
	}

	return true
}

// Children returns direct element children and rejects non-whitespace mixed content.
func Children(e document.Element) ([]document.Element, error) {
	_, n := tree.Unwrap(e)
	if n == nil {
		return nil, ErrSchema
	}

	for _, c := range n.Children {
		if c.Kind == tree.TextNode && !Space(c.Data) {
			return nil, ErrSchema
		}
	}

	return e.Children(), nil
}

// Simple returns bounded simple text and rejects child elements and attributes.
func Simple(e document.Element, maximum int) (string, error) {
	if len(e.Attributes()) != 0 {
		return "", ErrSchema
	}

	return SimpleText(e, maximum)
}

// SimpleText returns bounded direct text, ignoring comments/PIs and rejecting
// child elements. Attributes are validated separately by the caller.
func SimpleText(e document.Element, maximum int) (string, error) {
	if maximum < 0 || len(e.Children()) != 0 {
		return "", ErrSchema
	}

	_, node := tree.Unwrap(e)
	if node == nil {
		return "", ErrSchema
	}

	length := 0

	var single string

	segments := 0

	for _, child := range node.Children {
		if child.Kind != tree.TextNode {
			continue
		}

		if len(child.Data) > maximum-length {
			return "", ErrSchema
		}

		length += len(child.Data)
		single = child.Data
		segments++
	}

	if segments < 2 {
		return single, nil
	}

	var out strings.Builder
	out.Grow(length)

	for _, child := range node.Children {
		if child.Kind == tree.TextNode {
			out.WriteString(child.Data)
		}
	}

	return out.String(), nil
}

// EmptyContent reports whether content contains only XML whitespace, comments
// and processing instructions, without joining text segments.
func EmptyContent(e document.Element) bool {
	_, node := tree.Unwrap(e)
	if node == nil {
		return false
	}

	for _, child := range node.Children {
		switch child.Kind {
		case tree.TextNode:
			if !Space(child.Data) {
				return false
			}
		case tree.CommentNode, tree.PINode:
		default:
			return false
		}
	}

	return true
}

// ParseTime parses SAML UTC dateTime values with four-digit positive years and
// at most nine fractional digits. XML Schema permits 24:00:00 for midnight.
func ParseTime(s string) (time.Time, error) {
	t, err := xmltime.ParseUTC(s)
	if err != nil {
		return time.Time{}, ErrSchema
	}

	return t, nil
}

// Time formats a SAML timestamp in UTC.
func Time(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ID reports whether s is an allowed SAML ID.
func ID(s string) bool { return len(s) > 0 && len(s) <= 256 && tree.NCName(s) }

// URI reports whether s is a bounded absolute URI without XML whitespace.
func URI(s string) bool {
	if len(s) == 0 || len(s) > 2048 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}

	u, e := url.Parse(s)

	return e == nil && u.IsAbs()
}

// Endpoint checks a bounded absolute HTTPS endpoint, permitting HTTP only when requested.
func Endpoint(s string, allowHTTP bool) bool {
	u, e := url.Parse(s)
	return e == nil && len(s) <= 4096 && u.Host != "" && u.User == nil && u.Fragment == "" && u.Opaque == "" && (u.Scheme == "https" || (allowHTTP && u.Scheme == "http"))
}

// Bool parses an XML Schema boolean.
func Bool(s string) (bool, error) {
	switch s {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	}

	return false, ErrSchema
}

// Duration parses positive day/time XML Schema durations up to 365 days, with
// at most nine fractional second digits. Calendar years/months are unsupported.
func Duration(s string) (time.Duration, error) { // day/time subset; calendar years/months fail explicitly.
	if len(s) < 3 || len(s) > 64 || s[0] != 'P' {
		return 0, ErrSchema
	}

	s = s[1:]
	inTime := false
	seen := false
	last := 0

	var total time.Duration

	for s != "" {
		if s[0] == 'T' {
			if inTime {
				return 0, ErrSchema
			}

			inTime = true
			last = 1

			s = s[1:]
			if s == "" {
				return 0, ErrSchema
			}

			continue
		}

		i := durationNumberEnd(s)

		if i == 0 || i == len(s) {
			return 0, ErrSchema
		}

		kind := s[i]

		order, scale, valid := durationUnit(kind, inTime)
		if !valid {
			return 0, ErrSchema
		}

		if order <= last || kind != 'S' && strings.Contains(s[:i], ".") {
			return 0, ErrSchema
		}

		last = order

		amount, err := durationAmount(s[:i], scale)
		if err != nil || amount > 365*24*time.Hour-total {
			return 0, ErrSchema
		}

		total += amount
		seen = true
		s = s[i+1:]
	}

	if !seen || total <= 0 {
		return 0, ErrSchema
	}

	return total, nil
}

func durationAmount(s string, unit time.Duration) (time.Duration, error) {
	whole, fraction, hasFraction := strings.Cut(s, ".")
	if whole == "" || hasFraction && (unit != time.Second || len(fraction) == 0 || len(fraction) > 9) {
		return 0, ErrSchema
	}

	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || n < 0 || n > int64(365*24*time.Hour/unit) {
		return 0, ErrSchema
	}

	amount := time.Duration(n) * unit

	if hasFraction {
		nanos, err := strconv.ParseUint(fraction+strings.Repeat("0", 9-len(fraction)), 10, 32)
		if err != nil {
			return 0, ErrSchema
		}

		amount += time.Duration(nanos)
	}

	return amount, nil
}

func durationUnit(kind byte, inTime bool) (int, time.Duration, bool) {
	order := 0

	var scale time.Duration

	switch kind {
	case 'D':
		if inTime {
			return 0, 0, false
		}

		order = 1
		scale = 24 * time.Hour
	case 'H':
		if !inTime {
			return 0, 0, false
		}

		order = 2
		scale = time.Hour
	case 'M':
		if !inTime {
			return 0, 0, false
		}

		order = 3
		scale = time.Minute
	case 'S':
		if !inTime {
			return 0, 0, false
		}

		order = 4
		scale = time.Second
	default:
		return 0, 0, false
	}

	return order, scale, true
}

func durationNumberEnd(s string) int {
	i := 0
	for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
		i++
	}

	return i
}

// Node creates a private SAML element draft.
func Node(prefix, ns, local string) *tree.Node {
	return &tree.Node{Kind: tree.ElementNode, Prefix: prefix, Name: document.Name{Space: ns, Local: local}}
}

// Set sets an unqualified attribute on a private draft.
func Set(n *tree.Node, k, v string) {
	n.Attrs = append(n.Attrs, tree.Attribute{Name: document.Name{Local: k}, Value: v})
}

// Add attaches an owned child to a private draft.
func Add(n, c *tree.Node) { c.Parent = n; n.Children = append(n.Children, c) }

// Text adds text to a private draft.
func Text(n *tree.Node, s string) { Add(n, &tree.Node{Kind: tree.TextNode, Data: s}) }

// Document serializes and reparses a private draft to publish an immutable XML snapshot.
func Document(ctx context.Context, root *tree.Node) (*document.Document, error) {
	d := tree.FromNodes([]*tree.Node{root}, document.DefaultLimits())

	return tree.Reparse(ctx, d, document.DefaultLimits())
}

// Direct selects exactly one direct child with the required expanded name.
func Direct(e document.Element, n document.Name) (document.Element, error) {
	var out document.Element

	for _, c := range e.Children() {
		if c.Name() == n {
			if out.Valid() {
				return document.Element{}, ErrSchema
			}

			out = c
		}
	}

	if !out.Valid() {
		return out, fmt.Errorf("%w: missing %s", ErrSchema, n.Local)
	}

	return out, nil
}

// XMLLimits fills individual unset budgets without weakening supplied limits.
func XMLLimits(l document.Limits, capacity int) document.Limits {
	d := document.DefaultLimits()

	if l.MaxBytes == 0 || l.MaxBytes > capacity {
		l.MaxBytes = capacity
	}

	if l.MaxDepth == 0 {
		l.MaxDepth = d.MaxDepth
	}

	if l.MaxNodes == 0 {
		l.MaxNodes = d.MaxNodes
	}

	if l.MaxAttributesPerElement == 0 {
		l.MaxAttributesPerElement = d.MaxAttributesPerElement
	}

	if l.MaxInScopeNamespaces == 0 {
		l.MaxInScopeNamespaces = d.MaxInScopeNamespaces
	}

	if l.MaxNodeSetNodes == 0 {
		l.MaxNodeSetNodes = d.MaxNodeSetNodes
	}

	return l
}
