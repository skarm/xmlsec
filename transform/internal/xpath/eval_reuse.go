// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xpath

import (
	"context"
	"strings"
	"time"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Single-item results borrow one reusable slot until the next evaluation.
// StringValue separates multiple items with a single space, preserving its
// established display conversion independently of serialization parameters.
const (
	singleReuseResultItem    = 1
	reuseResultItemSeparator = ' '
)

// EvalState holds pre-allocated evaluation state that can be reused
// across multiple EvaluateReuse calls on the same Expression.
// Not safe for concurrent use.
//
// The returned Result from EvaluateReuse is only valid until the next
// EvaluateReuse call on the same EvalState — the result's backing
// storage may be overwritten.
type EvalState struct {
	// base is the evaluator configuration and starting focus. Resetting ec from
	// it prevents one call's invocation settings from becoming the next one's
	// defaults while retaining reusable configuration and operation-counter storage.
	base evalContext
	// ec retains mutable evaluation context and scratch storage between calls.
	ec      evalContext
	oneItem [singleReuseResultItem]xdm.Item // reusable backing for single-item results
	// nodes is the reusable backing of a result that is a node list.
	nodes resultNodes

	// explicitTime is true when the Evaluator had an explicitly configured
	// CurrentTime. When false, EvaluateReuse refreshes the clock per call so
	// fn:current-dateTime() does not stay frozen across reuse calls.
	explicitTime bool
}

// SetContextItem sets the non-node context item on the eval state.
// This is used when the context is an atomic value, and no node
// (e.g., sorting a sequence of atomic items).
//
// The item becomes the base focus, so it persists as the starting focus
// for subsequent EvaluateReuse calls (a reuse call with a non-nil node
// still overrides it for that call only).
func (s *EvalState) SetContextItem(item xdm.Item) {
	s.base.contextItem = item
	if item != nil {
		s.base.node = nil
	}
}

// SetPosition sets the context position on the eval state.
func (s *EvalState) SetPosition(pos int) { s.base.position = pos }

// SetSize sets the context size on the eval state.
func (s *EvalState) SetSize(size int) { s.base.size = size }

// EvaluateReuse evaluates the expression with reusable mutable state. The node
// argument overrides the base context node for this call when non-nil. Evaluation can
// allocate storage for intermediate values and results.
//
// The returned Result can borrow state storage and is valid only until the next call
// using that EvalState. Consume or copy needed values before reusing the state. An
// EvalState must not be used concurrently.
func (e *Expression) EvaluateReuse(ctx context.Context, state *EvalState, node xdm.Node) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	if err := e.requireCompiledProgram(); err != nil {
		return Result{}, err
	}

	previous := state.ec
	state.ec = state.base
	ec := &state.ec
	bindInvocationScope(ctx, ec)
	// Document outcomes are stable within one host invocation, including failed
	// loads, but a new invocation must observe the resolver again.
	if previous.invocation == ec.invocation {
		ec.docCache = previous.docCache
		ec.documentSnapshots = previous.documentSnapshots
	} else {
		ec.docCache = make(map[string]xdm.Node)
		ec.documentSnapshots = &documentSnapshotStore{}
	}

	ec.version = e.version

	if e.staticCollation != "" {
		ec.defaultCollation = e.staticCollation
	}

	if e.staticNamespaces != nil {
		ec.namespaces = e.staticNamespaces
		ec.defaultXMLNamespace = e.defaultXMLNamespace
	}

	ec.xpath10Compat = ec.xpath10Compat || e.version == xpathVersion10
	// A non-nil node overrides the base focus for this call only.
	if node != nil {
		ec.node = node
		ec.contextItem = nil
	}

	*ec.opCount = 0

	// Refresh the evaluator's fallback clock. The invocation can then override
	// it, as it does during an independent evaluation.
	if !state.explicitTime {
		now := time.Now()
		ec.currentTime = &now
	}

	applyBudget(ctx, ec)

	// Fast path for "." — skip eval entirely, reuse backing array
	if e.program != nil && e.program.stream.isContextItem {
		if ec.contextItem != nil {
			if value, ok := ec.contextItem.(xdm.AtomicValue); ok {
				if err := ChargeNumber(ctx, value); err != nil {
					return Result{}, err
				}
			}

			state.oneItem[0] = ec.contextItem

			return Result{seq: xdm.ItemSlice(state.oneItem[:])}, nil
		}

		if ec.node == nil {
			return Result{}, &xdm.Error{Code: lexicon.ErrXPDY0002, Message: errMsgContextItemAbsent}
		}

		state.oneItem[0] = nodeItemFor(ctx, ec, ec.node)

		return Result{seq: xdm.ItemSlice(state.oneItem[:])}, nil
	}

	if err := e.prefixPlan.Validate(ec.namespaces, e.staticNamespaces != nil || ec.strictPrefixes || e.version == xpathVersion10, ec.schemaDeclarations, ec.version); err != nil {
		return Result{}, err
	}

	seq, nodes, isNodes, err := e.evaluate(ctx, ec)
	if err != nil {
		return Result{}, err
	}

	if !isNodes {
		return Result{seq: seq}, nil
	}

	state.nodes = resultNodes{nodes: nodes}

	return Result{seq: &state.nodes}, nil
}

// StringValue returns the XPath string value of the result sequence.
// For single-node results, this returns the node's string value directly,
// avoiding the AtomizeItem → AtomicValue → AtomicToString round-trip.
func (r Result) StringValue() string {
	if rn, ok := r.seq.(*resultNodes); ok {
		switch len(rn.nodes) {
		case 0:
			return ""
		case singleReuseResultItem:
			return xdm.StringValue(rn.nodes[0])
		}
	}

	seq := r.items()
	if xdm.SequenceLen(seq) == 0 {
		return ""
	}

	if xdm.SequenceLen(seq) == singleReuseResultItem {
		switch v := seq.Get(0).(type) {
		case xdm.NodeItem:
			return xdm.StringValue(v.Node)
		case xdm.AtomicValue:
			s, _ := AtomicToString(v)
			return s
		}
	}

	var sb strings.Builder

	i := 0
	for item := range xdm.SequenceItems(seq) {
		if i > 0 {
			sb.WriteByte(reuseResultItemSeparator)
		}

		av, err := AtomizeItem(item)
		if err != nil {
			i++
			continue
		}

		s, err := AtomicToString(av)
		if err != nil {
			i++
			continue
		}

		sb.WriteString(s)

		i++
	}

	return sb.String()
}

// NewEvalState creates a reusable EvalState from this Evaluator's config.
// node sets the initial context node (may be nil).
//
// The returned EvalState is not safe for concurrent use. The Result from
// EvaluateReuse is only valid until the next EvaluateReuse call.
func (e Evaluator) NewEvalState(node xdm.Node) *EvalState {
	// Build the evaluation context through the shared initialization path so
	// the reuse state stays in lockstep with normal Evaluate: same nil-cfg
	// guard, same custom max-node limit, and the same complete set of copied
	// fields (preserved ID annotations, TraceWriter, etc.).
	return &EvalState{base: *e.newEvalCtx(node), explicitTime: e.cfg != nil && e.cfg.currentTime != nil}
}
