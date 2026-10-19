//go:build interop

package interop_test

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
)

// Mutable trees are confined to test-owned documents. Independent engines
// receive the resulting complete XML, so their canonicalization retains context.
func xmlDoc(t *testing.T, raw []byte) *document.Document {
	t.Helper()

	d, err := document.Parse(t.Context(), raw, document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	return d
}

func xmlBytes(t *testing.T, d *document.Document) []byte {
	t.Helper()

	b, err := d.XML(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func nodes(n *tree.Node, space, local string) []*tree.Node {
	var out []*tree.Node
	if n.Kind == tree.ElementNode && n.Name.Space == space && n.Name.Local == local {
		out = append(out, n)
	}

	for _, child := range n.Children {
		out = append(out, nodes(child, space, local)...)
	}

	return out
}

func one(t *testing.T, n *tree.Node, space, local string) *tree.Node {
	t.Helper()

	all := nodes(n, space, local)
	if len(all) != 1 {
		t.Fatalf("%s:%s count %d", space, local, len(all))
	}

	return all[0]
}

func attr(n *tree.Node, local string) string {
	for _, a := range n.Attrs {
		if a.Name.Space == "" && a.Name.Local == local {
			return a.Value
		}
	}

	return ""
}

func text(n *tree.Node) string {
	var b strings.Builder

	for _, c := range n.Children {
		if c.Kind == tree.TextNode {
			b.WriteString(c.Data)
		}
	}

	return b.String()
}

func setText(n *tree.Node, s string) {
	n.Children = []*tree.Node{{Kind: tree.TextNode, Data: s, Parent: n}}
}

func decode64(t *testing.T, s string) []byte {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func nodePath(n *tree.Node, d *document.Document) []int {
	var p []int

	for n != nil {
		siblings := tree.Children(d)
		if n.Parent != nil {
			siblings = n.Parent.Children
		}

		index := slices.Index(siblings, n)
		p = append(p, index+1)
		n = n.Parent
	}

	slices.Reverse(p)

	return p
}

func externalCanonical(t *testing.T, fixture *interopFixture, d *document.Document, n *tree.Node, algorithm string) []byte {
	t.Helper()

	base := algorithm
	comments := strings.HasSuffix(base, "WithComments")

	base = strings.TrimSuffix(strings.TrimSuffix(base, "WithComments"), "#")
	if strings.HasPrefix(algorithm, exc) {
		base = exc
	}

	mode := slices.Index([]string{c10, exc, c11}, base)
	if mode < 0 {
		t.Fatalf("unsupported external canonicalization %s", algorithm)
	}

	selection := "-"
	if n != nil {
		selection = selectionXPath(canonicalRequest{Subtree: nodePath(n, d)}, true)
	}

	path := write(t, filepath.Join(fixture.work, "external-canonical.xml"), xmlBytes(t, d))
	data, _ := command(t, fixture, true, nil, cOracle(t, fixture), path, strconv.Itoa(mode), strconv.Itoa(boolInt(comments)), selection, "-")

	return data
}

func equalXML(t *testing.T, fixture *interopFixture, a, b []byte) {
	t.Helper()
	da, db := xmlDoc(t, a), xmlDoc(t, b)

	left, right := externalCanonical(t, fixture, da, nil, c10+"#WithComments"), externalCanonical(t, fixture, db, nil, c10+"#WithComments")
	if !bytes.Equal(left, right) {
		t.Fatalf("XML context changed\nleft %s\nright %s", left, right)
	}
}

func clearCipherValues(t *testing.T, raw []byte) []byte {
	t.Helper()

	d := xmlDoc(t, raw)
	for _, n := range nodes(tree.Root(d), enc, "CipherValue") {
		n.Children = nil
	}

	return xmlBytes(t, d)
}

func corruptCipher(t *testing.T, raw []byte) []byte {
	t.Helper()
	d := xmlDoc(t, raw)
	envelope := one(t, tree.Root(d), enc, nameEncryptedData)

	var data *tree.Node

	for _, c := range envelope.Children {
		if c.Name.Space == enc && c.Name.Local == nameCipherData {
			data = c
		}
	}

	if data == nil {
		t.Fatal(nameCipherData)
	}

	value := one(t, data, enc, "CipherValue")

	b := decode64(t, text(value))
	if len(b) == 0 {
		t.Fatal("ciphertext empty")
	}

	b[len(b)-1] ^= 1
	setText(value, base64.StdEncoding.EncodeToString(b))

	return xmlBytes(t, d)
}

func xmlElement(t *testing.T, d *document.Document, n *tree.Node) []byte {
	t.Helper()

	snapshot, cloneErr := tree.Clone(t.Context(), d)
	if cloneErr != nil {
		t.Fatal(cloneErr)
	}

	path := nodePath(n, d)

	current := tree.Children(snapshot)[path[0]-1]
	for _, i := range path[1:] {
		current = current.Children[i-1]
	}
	// Materialize in-scope namespaces on the extracted envelope.
	for _, a := range tree.Wrap(d, n).NamespaceNodes() {
		prefix := a.Name().Local
		if prefix == "xml" {
			continue
		}

		seen := false

		for _, ns := range current.NS {
			if ns.Prefix == prefix {
				seen = true
			}
		}

		if !seen {
			current.NS = append(current.NS, tree.Namespace{Prefix: prefix, URI: a.Value()})
		}
	}

	current.Parent = nil

	return xmlBytes(t, tree.FromNodes([]*tree.Node{current}, document.DefaultLimits()))
}

func nativeKeyArgs(mode, keyName string) (string, string) {
	if mode == nameRsa {
		return flagPubkeyPem, "--privkey-pem"
	}

	arg := "--aeskey"
	if keyName != "" {
		arg += ":" + keyName
	}

	return arg, arg
}

func copyTask(original map[string]any) map[string]any {
	m := make(map[string]any, len(original))
	for k, v := range original {
		m[k] = v
	}

	return m
}

func cipherReference(t *testing.T, raw []byte, uri string, encoded bool) ([]byte, []byte) {
	t.Helper()
	d := xmlDoc(t, raw)
	envelope := one(t, tree.Root(d), enc, nameEncryptedData)

	var cd *tree.Node

	for _, n := range envelope.Children {
		if n.Name.Space == enc && n.Name.Local == nameCipherData {
			cd = n
		}
	}

	if cd == nil {
		t.Fatal(nameCipherData)
	}

	body := decode64(t, text(one(t, cd, enc, "CipherValue")))
	ref := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Space: enc, Local: "CipherReference"}, Prefix: cd.Prefix, Parent: cd, Attrs: []tree.Attribute{{Name: tree.Name{Local: "URI"}, Value: uri}}}

	cd.Children = []*tree.Node{ref}
	if encoded {
		tr := &tree.Node{Kind: tree.ElementNode, Name: tree.Name{Space: enc, Local: "Transforms"}, Prefix: cd.Prefix, Parent: ref}
		ref.Children = []*tree.Node{tr}
		tr.Children = []*tree.Node{{Kind: tree.ElementNode, Name: tree.Name{Space: ds, Local: "Transform"}, Prefix: "ds", Parent: tr, NS: []tree.Namespace{{Prefix: "ds", URI: ds}}, Attrs: []tree.Attribute{{Name: tree.Name{Local: "Algorithm"}, Value: ds + "base64"}}}}
		body = []byte(" \n" + base64.StdEncoding.EncodeToString(body) + "\t\r")
	}

	return xmlBytes(t, d), body
}
