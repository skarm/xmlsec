package tree

import (
	"context"
	"fmt"
)

// CheckSnapshotLimits applies a consumer's policy to an existing immutable
// snapshot without serializing, copying or parsing it again.
func CheckSnapshotLimits(ctx context.Context, d *Document, limits Limits) error {
	if ctx == nil || d == nil {
		return ErrMalformed
	}

	if err := limits.Validate(); err != nil {
		return err
	}

	if d.inputBytes > limits.MaxBytes {
		return fmt.Errorf("%w: input bytes", ErrLimit)
	}

	checker := snapshotLimitChecker{ctx: ctx, document: d, limits: limits, scope: newNamespaceContext(nil)}

	for _, n := range d.children {
		if err := checker.visit(n, 0); err != nil {
			return err
		}
	}

	return ctx.Err()
}

type snapshotLimitChecker struct {
	ctx      context.Context
	document *Document
	limits   Limits
	scope    namespaceContext
	count    int
	bytes    int
}

func (c *snapshotLimitChecker) visit(n *Node, depth int) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}

	c.count++
	if c.count > c.limits.MaxNodes {
		return fmt.Errorf("%w: nodes", ErrLimit)
	}

	c.bytes += len(n.Data) + len(n.Name.Local) + len(n.Prefix) + len(n.Name.Space)
	if n.Kind == ElementNode {
		mark := c.scope.push(n.NS)
		defer c.scope.pop(mark)

		if c.scope.size() > c.limits.namespaceLimit() {
			return fmt.Errorf("%w: in-scope namespaces", ErrLimit)
		}

		depth++
		if depth > c.limits.MaxDepth {
			return fmt.Errorf("%w: depth", ErrLimit)
		}

		if len(n.Attrs)+len(n.NS) > c.limits.MaxAttributesPerElement {
			return fmt.Errorf("%w: attributes", ErrLimit)
		}
	}

	for _, a := range n.Attrs {
		c.bytes += len(a.Name.Local) + len(a.Name.Space) + len(a.Prefix) + len(a.Value)
	}

	for _, ns := range n.NS {
		c.bytes += len(ns.Prefix) + len(ns.URI)
	}

	if c.document.inputBytes == 0 && c.bytes > c.limits.MaxBytes {
		return fmt.Errorf("%w: node storage bytes", ErrLimit)
	}

	for _, child := range n.Children {
		if err := c.visit(child, depth); err != nil {
			return err
		}
	}

	return nil
}
