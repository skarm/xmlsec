package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

type request struct {
	Select    *[]selector `json:"select"`
	XML       string      `json:"xml"`
	Algorithm string      `json:"algorithm"`
	Input     []byte      `json:"input,omitempty"`
	Prefixes  []string    `json:"prefixes"`
	Subtree   []int       `json:"subtree"`
	Comments  bool        `json:"comments"`
	Describe  bool        `json:"describe"`
}

type response struct {
	Canonical []byte     `json:"canonical,omitempty"`
	Nodes     []selector `json:"nodes,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type selector struct {
	Path   []int  `json:"path"`
	Kind   string `json:"kind,omitempty"`
	Local  string `json:"local,omitempty"`
	Space  string `json:"space,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), 32<<20)

	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		var (
			r   request
			out response
		)
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			out.Error = err.Error()
		} else {
			var err error

			out, err = process(r)
			if err != nil {
				out.Error = err.Error()
			}
		}

		if err := encoder.Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func process(r request) (response, error) {
	data := []byte(r.XML)
	if r.Input != nil {
		data = r.Input
	}

	d, err := document.Parse(context.Background(), data, document.DefaultLimits())
	if err != nil {
		return response{}, err
	}

	out := response{}

	if r.Describe {
		var walk func(document.Node, []int)

		walk = func(n document.Node, path []int) {
			out.Nodes = append(out.Nodes, selector{Path: append([]int{}, path...), Kind: n.Kind().String()})
			if e, ok := n.Element(); ok {
				for _, a := range e.NamespaceNodes() {
					out.Nodes = append(out.Nodes, selector{Path: append([]int{}, path...), Kind: "namespace", Prefix: a.Name().Local})
				}

				for _, a := range e.AttributeNodes() {
					out.Nodes = append(out.Nodes, selector{Path: append([]int{}, path...), Kind: nameAttribute, Local: a.Name().Local, Space: a.Name().Space})
				}
			}

			for i, child := range n.Children() {
				walk(child, append(append([]int{}, path...), i+1))
			}
		}
		walk(d.Node(), nil)
	}

	var b bytes.Buffer

	opt := c14n.Options{Algorithm: r.Algorithm, WithComments: r.Comments, InclusivePrefixes: r.Prefixes}
	if err := writeSelection(&b, d, r, opt); err != nil {
		return out, err
	}

	out.Canonical = b.Bytes()

	return out, nil
}

func resolve(d *document.Document, s selector) (document.Node, error) {
	n := d.Node()
	for _, index := range s.Path {
		children := n.Children()
		if index < 1 || index > len(children) {
			return document.Node{}, errors.New("invalid selector path")
		}

		n = children[index-1]
	}

	if s.Kind == nameAttribute || s.Kind == "namespace" {
		e, ok := n.Element()
		if !ok {
			return document.Node{}, errors.New("axis owner is not an element")
		}

		if s.Kind == nameAttribute {
			for _, a := range e.AttributeNodes() {
				if a.Name() == (document.Name{Local: s.Local, Space: s.Space}) {
					return a, nil
				}
			}
		} else {
			for _, a := range e.NamespaceNodes() {
				if a.Name().Local == s.Prefix {
					return a, nil
				}
			}
		}

		return document.Node{}, errors.New("axis node does not exist")
	}

	if s.Kind != "" && s.Kind != n.Kind().String() {
		return document.Node{}, errors.New("node kind mismatch")
	}

	return n, nil
}

func writeSelection(dst io.Writer, doc *document.Document, r request, opt c14n.Options) error {
	if r.Select != nil {
		nodes := make([]document.Node, 0, len(*r.Select))
		for _, selection := range *r.Select {
			node, err := resolve(doc, selection)
			if err != nil {
				return err
			}

			nodes = append(nodes, node)
		}

		set, err := document.NewNodeSet(doc, nodes...)
		if err != nil {
			return err
		}

		return c14n.WriteNodeSet(context.Background(), dst, set, opt)
	}

	if r.Subtree != nil {
		node, err := resolve(doc, selector{Path: r.Subtree})
		if err != nil {
			return err
		}

		element, ok := node.Element()
		if !ok {
			return errors.New("subtree target is not an element")
		}

		return c14n.WriteElement(context.Background(), dst, element, opt)
	}

	return c14n.WriteDocument(context.Background(), dst, doc, opt)
}
