package tree

import (
	"context"
	"io"
	"iter"
)

// Reparse serializes a private draft into the incremental XML parser, producing
// a validated immutable snapshot without a complete intermediate XML buffer.
// The draft and resulting tree both occupy memory proportional to their content.
func Reparse(ctx context.Context, draft *Document, limits Limits) (*Document, error) {
	if ctx == nil || draft == nil {
		return nil, ErrMalformed
	}

	return ParseProduced(ctx, func(dst io.Writer) error {
		_, err := draft.WriteXML(ctx, dst, limits.MaxBytes)
		return err
	}, limits)
}

// ParseProduced parses XML as produce writes it, without retaining serialized
// bytes. The producer is stopped when parsing fails; its final error is observed
// before a document is returned. The resulting XML tree remains materialized.
func ParseProduced(ctx context.Context, produce func(io.Writer) error, limits Limits) (*Document, error) {
	if ctx == nil || produce == nil {
		return nil, ErrMalformed
	}

	if err := limits.Validate(); err != nil {
		return nil, err
	}

	sequence := func(yield func([]byte, error) bool) {
		writer := snapshotWriter{yield: yield}
		if err := produce(&writer); err != nil && !writer.stopped {
			yield(nil, err)
		}
	}

	next, stop := iter.Pull2(sequence)
	defer stop()

	source := snapshotReader{next: next}

	return ParseReader(ctx, &source, limits)
}

// ReplaceDraft replaces selected with a privately owned replacement header,
// copying only ancestor headers and child lists. Other nodes are borrowed and
// must only be serialized, never mutated through the draft. Parent links on the
// replacement path belong to the draft; Reparse owns all nodes in the result.
func ReplaceDraft(ctx context.Context, doc *Document, selected, replacement *Node) (*Document, error) {
	if ctx == nil || doc == nil || selected == nil || replacement == nil || selected.Kind != ElementNode || replacement.Kind != ElementNode || selected == replacement {
		return nil, ErrMalformed
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	imported := replacement

	original := selected
	for original.Parent != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		parent := *original.Parent
		parent.Children = append([]*Node(nil), parent.Children...)
		found := false

		for i, child := range parent.Children {
			if child == original {
				parent.Children[i] = imported
				found = true

				break
			}
		}

		if !found {
			return nil, ErrMalformed
		}

		imported.Parent = &parent
		imported = &parent
		original = original.Parent
	}

	if original != doc.root {
		return nil, ErrMalformed
	}

	imported.Parent = nil

	children := append([]*Node(nil), doc.children...)
	for i, node := range children {
		if node == doc.root {
			children[i] = imported
			break
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return FromNodes(children, doc.limits), nil
}

type snapshotWriter struct {
	yield   func([]byte, error) bool
	stopped bool
}

func (w *snapshotWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	if !w.yield(data, nil) {
		w.stopped = true
		return 0, io.ErrClosedPipe
	}

	return len(data), nil
}

type snapshotReader struct {
	next    func() ([]byte, error, bool)
	pending []byte
}

func (r *snapshotReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}

	if len(r.pending) == 0 {
		value, err, ok := r.next()
		if err != nil {
			return 0, err
		}

		if !ok {
			return 0, io.EOF
		}

		r.pending = value
	}

	n := copy(dst, r.pending)
	r.pending = r.pending[n:]

	return n, nil
}
