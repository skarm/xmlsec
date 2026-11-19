// Copyright (c) 2026 xmlsec contributors. MIT License.

package xpath

import (
	"context"
	"errors"
	"maps"

	"github.com/skarm/xmlsec/transform/internal/pattern"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// ErrBudget reports exhaustion of the invocation's shared resource budget.
var ErrBudget = errors.New("XML execution resource limit exceeded")

// ControlFailure preserves cancellation and implementation limits instead of
// converting them into recoverable language errors. Ordinary errors return nil.
func ControlFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrBudget) || errors.Is(err, ErrOpLimit) ||
		errors.Is(err, ErrNodeSetLimit) || errors.Is(err, ErrRecursionLimit) || errors.Is(err, pattern.ErrLimit) {
		return err
	}

	return nil
}

// WithBudget shares limits across nested XSLT and XPath calls in one goroutine.
func WithBudget(ctx context.Context, operations, nodes, bytes, depth int) context.Context {
	return context.WithValue(ctx, budgetKey{}, &budget{operations: operations, nodes: nodes, bytes: bytes, depth: depth})
}

// Charge checks cancellation and charges work before further computation.
func Charge(ctx context.Context, n int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b := getBudget(ctx)
	if b == nil {
		return nil
	}

	if n < 0 || n > b.operations-b.usedOperations {
		return ErrBudget
	}

	b.usedOperations += n

	return nil
}

// DepthLimit returns the invocation's recursion limit, if configured.
func DepthLimit(ctx context.Context, fallback int) int {
	if b := getBudget(ctx); b != nil {
		return min(b.depth, fallback)
	}

	return fallback
}

// NodeLimit returns the invocation's collection/tree size limit, if configured.
func NodeLimit(ctx context.Context, fallback int) int {
	if b := getBudget(ctx); b != nil {
		return b.nodes
	}

	return fallback
}

// WithFunctions installs an immutable application registry for one invocation.
func WithFunctions(ctx context.Context, functions map[QualifiedName]Function) context.Context {
	return context.WithValue(ctx, functionsKey{}, functions)
}

// FunctionsFromContext returns the invocation's application function registry.
func FunctionsFromContext(ctx context.Context) map[QualifiedName]Function {
	functions, _ := ctx.Value(functionsKey{}).(map[QualifiedName]Function)
	return functions
}

// ChargeTree bounds constructed trees, including temporary variable trees.
func ChargeTree(ctx context.Context, node xdm.Node) error {
	const constructedTreeBaseWork = 1

	b := getBudget(ctx)
	if b == nil || node == nil {
		return nil
	}

	if err := Charge(ctx, constructedTreeBaseWork); err != nil {
		return err
	}

	return b.chargeTree(ctx, node, 0)
}

func (b *budget) chargeTree(ctx context.Context, node xdm.Node, ancestors int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if b.usedNodes >= b.nodes {
		return ErrBudget
	}

	childAncestors := 0

	switch kind := node.Type(); kind {
	case xdm.ElementNode, xdm.DocumentNode:
		childAncestors = ancestors + 1
	default:
		copies := 1
		if kind == xdm.TextNode || kind == xdm.CDATASectionNode {
			copies += ancestors
		}

		// Text contributes to its own string value and to the string values
		// of its containing elements and document. Other node kinds charge
		// only their own data.
		size := len(xdm.CharacterData(node))
		remaining := b.bytes - b.usedBytes

		if remaining < 0 || size > remaining/copies {
			return ErrBudget
		}

		b.usedBytes += size * copies
	}

	b.usedNodes++

	for child := node.FirstChild(); child != nil; child = child.NextSibling() {
		if err := b.chargeTree(ctx, child, childAncestors); err != nil {
			return err
		}
	}

	return nil
}

// ChargeTreeNodes reserves constructed nodes whose contents are accounted for
// separately, such as shallow shells around an already charged subtree.
func ChargeTreeNodes(ctx context.Context, count int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	b := getBudget(ctx)
	if b == nil {
		return nil
	}

	if count < 0 || count > b.nodes-b.usedNodes {
		return ErrBudget
	}

	b.usedNodes += count

	return nil
}

// ChargeString bounds string construction before concatenation/allocation.
func ChargeString(ctx context.Context, sizes ...int) error {
	b := getBudget(ctx)
	if b == nil {
		return ctx.Err()
	}

	for _, n := range sizes {
		if n < 0 || n > b.bytes-b.usedBytes {
			return ErrBudget
		}

		b.usedBytes += n
	}

	return ctx.Err()
}

// WithEnvironment supplies only the application's explicit environment snapshot.
func WithEnvironment(ctx context.Context, values map[string]string) context.Context {
	return context.WithValue(ctx, environmentKey{}, values)
}

type (
	budgetKey struct{}
	budget    struct {
		operations     int
		nodes          int
		bytes          int
		depth          int
		usedOperations int
		usedNodes      int
		usedBytes      int
	}
)

func getBudget(ctx context.Context) *budget {
	if ctx == nil {
		return nil
	}

	b, _ := ctx.Value(budgetKey{}).(*budget)

	return b
}

func applyBudget(ctx context.Context, ec *evalContext) {
	ec.xmlSchemaVersion = XMLSchemaVersion(ctx)
	if value, ok := evaluationContextFrom(ctx); ok {
		ec.currentTime = &value.CurrentTime

		ec.implicitTimezone = value.Timezone
		if value.Language != "" {
			ec.defaultLanguage = value.Language
		}

		ec.traceWriter = value.Trace
		if ec.collectionResolver == nil {
			ec.collectionResolver = value.Collections
		}
	}

	if functions := FunctionsFromContext(ctx); len(functions) > 0 {
		merged := make(map[QualifiedName]Function, len(functions)+len(ec.fnsNS))
		maps.Copy(merged, functions)
		maps.Copy(merged, ec.fnsNS)
		ec.fnsNS = merged
	}

	if b := getBudget(ctx); b != nil {
		ec.maxNodes = min(ec.maxNodes, b.nodes)
		ec.maxRecursionDepth = min(ec.maxRecursionDepth, b.depth)
		ec.opLimit = b.operations
	}
}

type functionsKey struct{}

type environmentKey struct{}

func environmentFrom(ctx context.Context) map[string]string {
	values, _ := ctx.Value(environmentKey{}).(map[string]string)
	return values
}
