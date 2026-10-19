// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"context"
	"maps"
	"net/url"
	"strings"

	"github.com/skarm/xmlsec/transform/internal/xdm"
	"github.com/skarm/xmlsec/transform/internal/xdm/lexicon"
	"github.com/skarm/xmlsec/transform/internal/xpath"
)

// paramDocPresence records which plain-boolean serialization parameters a
// parameter-document explicitly supplied. These flags are deliberately kept off
// the public OutputDef: a plain bool cannot distinguish "omitted" from "explicit
// false", and foldParamDocOverrides consults them so an omitted parameter-document
// value leaves an inherited xsl:output default intact instead of clobbering it
// with the Go zero value. They travel alongside the parameter-document delta
// OutputDef (on the compiled instruction or the per-invocation cache).
type paramDocPresence struct {
	indent              bool
	byteOrderMark       bool
	allowDuplicateNames bool
	undeclarePrefixes   bool
}

// getParamDocOutputDef returns the effective parameter-document OutputDef for
// a result-document instruction, checking the per-invocation cache on
// execContext first, then falling back to the compiled instruction's field.
func (ec *execContext) getParamDocOutputDef(inst *resultDocumentInst) *OutputDef {
	if od, ok := ec.paramDocOutputDefs[inst]; ok {
		return od
	}

	return inst.ParameterDocOutputDef
}

// getParamDocPresence returns the plain-boolean presence flags that accompany
// the effective parameter-document delta, mirroring getParamDocOutputDef's
// cache-then-instruction lookup so the runtime AVT and compile-time static
// parameter-document paths stay in sync.
func (ec *execContext) getParamDocPresence(inst *resultDocumentInst) paramDocPresence {
	if p, ok := ec.paramDocPresences[inst]; ok {
		return p
	}

	return inst.ParameterDocPresence
}

// execDocument implements xsl:document: creates a document node wrapping
// the result of executing the body.
func (ec *execContext) execDocument(ctx context.Context, inst *documentInst) error {
	tmpDoc := xdm.NewDefaultDocument()
	frame := &outputFrame{doc: tmpDoc, current: tmpDoc}

	ec.outputStack = append(ec.outputStack, frame)
	if err := ec.executeSequenceConstructor(ctx, inst.Body); err != nil {
		ec.outputStack = ec.outputStack[:len(ec.outputStack)-1]
		return err
	}

	ec.outputStack = ec.outputStack[:len(ec.outputStack)-1]

	// Apply type validation (xsl:document type="...").
	if inst.TypeName != "" {
		// XTTE1550: document must have exactly one element child.
		if err := validateDocumentStructure(tmpDoc); err != nil {
			return err
		}
	}

	// Apply validation if requested (xsl:document validation="strict"|"lax").
	if v := inst.Validation; v == validationStrict || v == validationLax {
		if v == validationStrict {
			if err := validateDocumentStructure(tmpDoc); err != nil {
				return err
			}
		}
	}

	preserveAnnotations := inst.Validation == validationPreserve || inst.Validation == validationStrict || inst.Validation == validationLax || inst.TypeName != ""

	return ec.emitConstructedDocument(tmpDoc, preserveAnnotations)
}

// emitConstructedDocument preserves document items in sequence/simple content
// output and preserves node identity when annotations belong to those nodes.
func (ec *execContext) emitConstructedDocument(doc *xdm.Document, preserveAnnotations bool) error {
	out := ec.currentOutput()

	captureDocument := out.sequenceMode || (out.captureItems && out.current != nil && out.current.Type() != xdm.DocumentNode)
	if doc.FirstChild() == nil {
		if captureDocument {
			out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: doc})
			out.noteOutput()
		} else if !out.wherePopulated {
			out.prevWasAtomic = false
		}

		return nil
	}

	if captureDocument {
		out.pendingItems = append(out.pendingItems, xdm.NodeItem{Node: doc})
		out.noteOutput()

		return nil
	}

	if out.wherePopulated {
		return ec.addNode(doc)
	}

	if preserveAnnotations {
		return ec.moveAnnotatedDocumentChildren(doc)
	}

	for child := range xdm.Children(doc) {
		if err := ec.copyNodeToOutput(child); err != nil {
			return err
		}
	}

	return nil
}

func (ec *execContext) moveAnnotatedDocumentChildren(doc *xdm.Document) error {
	var children []xdm.Node

	for child := range xdm.Children(doc) {
		if xdm.IsXDMChild(child) {
			children = append(children, child)
		}
	}

	for _, child := range children {
		xdm.UnlinkNode(child.(xdm.MutableNode)) //nolint:forcetypeassert

		if err := ec.addNode(child); err != nil {
			return err
		}
	}

	return nil
}

// isItemOutputMethod returns true when the current effective output method
// supports non-node items (maps, arrays, function items).
func (ec *execContext) isItemOutputMethod() bool {
	return isItemSerializationMethod(ec.currentResultDocMethod)
}

// resolveResultDocFormat returns the effective format name for a result-document
// instruction, evaluating the format avt if present.
// Returns an error for XTDE0290 (prefix not bound) or XTDE1460 (invalid QName).
func (ec *execContext) resolveResultDocFormat(ctx context.Context, inst *resultDocumentInst) (string, error) {
	if inst.FormatAVT != nil {
		v, err := inst.FormatAVT.evaluate(ctx, ec.contextNode)
		if err != nil {
			// A dynamic error raised while evaluating the format AVT must be
			// surfaced, not swallowed: silently falling back to the static
			// format would hide a transformation failure from the caller.
			return "", err
		}

		v = strings.TrimSpace(v)
		if v != "" && !strings.HasPrefix(v, "Q{") {
			// XTDE0290: prefix must have a namespace binding
			if prefix, _, ok := strings.Cut(v, ":"); ok {
				if _, ok := inst.NSBindings[prefix]; !ok {
					return "", dynamicError(errCodeXTDE0290,
						"prefix %q in result-document format has no namespace binding", prefix)
				}
			}
		}

		return resolveQName(v, inst.NSBindings), nil
	}

	return inst.Format, nil
}

// resolveResultDocMethod returns the effective output method for a result-document
// instruction, considering the method avt, compile-time method, named format, and
// default output definition.
func (ec *execContext) resolveResultDocMethod(ctx context.Context, inst *resultDocumentInst) string {
	// Runtime avt takes priority.
	if inst.MethodAVT != nil {
		v, err := inst.MethodAVT.evaluate(ctx, ec.contextNode)
		if err == nil {
			return strings.TrimSpace(v)
		}
	}
	// Compile-time method attribute (may have been set from parameter-document).
	if inst.Method != "" {
		return inst.Method
	}
	// Parameter-document output definition.
	if pd := ec.getParamDocOutputDef(inst); pd != nil && pd.Method != "" {
		return pd.Method
	}
	// Named format.
	format, _ := ec.resolveResultDocFormat(ctx, inst)
	if format != "" {
		if outDef, ok := ec.effectiveOutputs()[format]; ok {
			return outDef.Method
		}
	}
	// Default output definition.
	if outDef, ok := ec.effectiveOutputs()[""]; ok {
		return outDef.Method
	}

	return methodXML
}

// commitPrimaryOutputState publishes the serialization overrides and
// character-map state that a primary xsl:result-document contributes to the
// final primary output. It is the single commit point shared by EVERY primary
// sub-branch (default direct-write, build-tree="no", type="...",
// validation="strict|lax"): each branch evaluates the preflight overrides up
// front (before touching the primary tree) and calls this only after its body
// and post-body checks succeed. Calling it uniformly guarantees that the
// serialization AVTs and character maps declared on a primary result-document
// take effect regardless of which validation/type/build-tree branch handled it.
func (ec *execContext) commitPrimaryOutputState(inst *resultDocumentInst, effectiveFormat string, primaryOverrides *OutputDef) {
	// Propagate character map names to the primary output frame.
	// Include maps from the named format (xsl:output) first, then
	// maps from xsl:result-document itself (higher priority).
	var allMaps []string

	if effectiveFormat != "" {
		if fmtDef, ok := ec.effectiveOutputs()[effectiveFormat]; ok {
			allMaps = append(allMaps, fmtDef.UseCharacterMaps...)
			// Also propagate resolved character maps from parameter-document.
			// Clone the compiled map so the later maps.Copy merge below never
			// mutates the compiled format's ResolvedCharMap.
			if len(fmtDef.ResolvedCharMap) > 0 {
				ec.primaryResolvedCharMap = maps.Clone(fmtDef.ResolvedCharMap)
			}
		}
	}

	allMaps = append(allMaps, inst.UseCharacterMaps...)
	if len(allMaps) > 0 {
		ec.primaryCharacterMaps = allMaps
		// Resolve character maps now while currentPackage is correct
		// (package-scoped isolation). Merge into primaryResolvedCharMap.
		resolved := resolveCharacterMaps(ec.effectiveStylesheet(), allMaps)
		if len(resolved) > 0 {
			if ec.primaryResolvedCharMap == nil {
				ec.primaryResolvedCharMap = resolved
			} else {
				maps.Copy(ec.primaryResolvedCharMap, resolved)
			}
		}
	}
	// Capture serialization parameter overrides from xsl:result-document.
	// These were already evaluated up front (before any primary output was
	// emitted) so that an AVT error releases the URI reservation without
	// leaving partial primary output behind.
	if primaryOverrides != nil {
		ec.primaryOutputOverrides = primaryOverrides
	}
}

func (ec *execContext) execResultDocument(ctx context.Context, inst *resultDocumentInst) error {
	// XTDE1480: xsl:result-document is not allowed in a temporary output state.
	if ec.temporaryOutputDepth > 0 {
		return dynamicError(errCodeXTDE1480, "xsl:result-document is not allowed while in temporary output state")
	}

	href := ""

	if inst.Href != nil {
		var err error

		href, err = inst.Href.evaluate(ctx, ec.contextNode)
		if err != nil {
			return err
		}
	}

	isPrimary := href == ""

	// XTDE1490 duplicate detection keys on the canonical (resolved) output URI,
	// not the raw href: distinct hrefs that resolve to the same absolute URI
	// (e.g. "a/../out.xml" and "out.xml" under the same base) target the same
	// document and must collide. The primary output (empty href) always keys on
	// "" so that the implicit-primary claim tracked elsewhere stays consistent.
	dupKey := href
	if !isPrimary {
		dupKey = canonicalResultURIKey(href, ec.currentOutputURI)
	}

	if _, used := ec.usedResultURIs[dupKey]; used {
		return dynamicError(errCodeXTDE1490, "two result documents written to same URI: %q", dupKey)
	}

	if isPrimary && ec.primaryClaimedImplicitly {
		return dynamicError(errCodeXTRE1495, "primary output URI already has implicit content")
	}

	// Reserve the canonical URI so a concurrent/nested result-document targeting
	// the same URI collides, but treat the reservation as provisional until the
	// result document is actually committed. Any error before commit (e.g. a
	// format AVT that raises a dynamic error, a failed parameter-document load,
	// or a body that throws) must release the reservation. Otherwise an
	// xsl:result-document caught inside xsl:try would leave its URI permanently
	// claimed, making an xsl:catch that writes the same href fail with a
	// spurious XTDE1490 even though no result document was ever written there.
	ec.usedResultURIs[dupKey] = struct{}{}

	committed := false
	defer func() {
		if !committed {
			delete(ec.usedResultURIs, dupKey)
		}
	}()

	// Resolve the effective format name (static or avt).
	effectiveFormat, fmtErr := ec.resolveResultDocFormat(ctx, inst)
	if fmtErr != nil {
		return fmtErr
	}

	// XTDE1460: the format attribute must reference a declared xsl:output.
	if effectiveFormat != "" {
		if _, ok := ec.effectiveOutputs()[effectiveFormat]; !ok {
			return dynamicError(errCodeXTDE1460,
				"xsl:result-document format %q does not match any declared xsl:output", effectiveFormat)
		}
	}

	if err := ec.resolveResultParameterDocument(ctx, inst); err != nil {
		return err
	}

	itemSep, err := ec.resolveResultItemSeparator(ctx, inst, effectiveFormat)
	if err != nil {
		return err
	}

	// Track the current output URI for current-output-uri().
	// For secondary outputs, resolve relative href against the current output URI
	// using the SAME URI-preserving resolver as the XTDE1490 duplicate key
	// (canonicalResultURIKey). xdm.BuildURI strips the file: scheme for file:
	// bases, so a nested result-document inside a secondary output would compute a
	// scheme-stripped base ("/base/dir/inner.xml") that no longer matches the
	// duplicate key's scheme-preserving form ("file:///base/dir/inner.xml"),
	// causing a relative href and its absolute file: equivalent to miss inside the
	// secondary output. Canonicalizing here keeps both forms consistent.
	savedOutputURI := ec.currentOutputURI
	if href != "" {
		ec.currentOutputURI = canonicalResultURIKey(href, savedOutputURI)
	}
	// For primary output (href==""), currentOutputURI stays unchanged.
	defer func() { ec.currentOutputURI = savedOutputURI }()

	if isPrimary {
		err = ec.execPrimaryResultDocument(ctx, inst, effectiveFormat, itemSep)
	} else {
		err = ec.execSecondaryResultDocument(ctx, inst, effectiveFormat, itemSep, href, dupKey)
	}

	if err != nil {
		return err
	}

	committed = true

	return nil
}

// canonicalResultURIKey produces a canonical key for XTDE1490 duplicate
// detection. Unlike xdm.BuildURI (which strips the file: scheme for file:
// bases, turning "file:///d/out.xml" into "/d/out.xml"), this resolves the
// href as a URI and PRESERVES the scheme/host for both absolute and relative
// hrefs. That ensures a relative href ("out.xml") and the equivalent absolute
// href ("file:///d/out.xml") under the same base collapse to the same key, so
// two result documents denoting the same file are detected as duplicates.
func canonicalResultURIKey(href, base string) string {
	ref, err := url.Parse(href)
	if err != nil {
		return href
	}

	if ref.IsAbs() {
		// Collapse "." / ".." dot-segments so that
		// "file:///base/dir/a/../out.xml" and "file:///base/dir/out.xml" produce
		// the SAME key (XTDE1490 duplicate detection). Resolving an absolute
		// hierarchical reference against itself runs RFC 3986 remove_dot_segments
		// while preserving the scheme/authority.
		return ref.ResolveReference(ref).String()
	}

	if base == "" {
		return href
	}

	baseURL, err := url.Parse(base)
	if err != nil || !baseURL.IsAbs() {
		// Without a usable absolute base we cannot canonicalize URI-wise;
		// fall back to xdm.BuildURI's filesystem-style resolution so that
		// distinct relative hrefs denoting the same path still collide.
		if resolved := xdm.BuildURI(href, base); resolved != "" {
			return resolved
		}

		return href
	}

	return baseURL.ResolveReference(ref).String()
}

func (ec *execContext) resolveResultParameterDocument(ctx context.Context, inst *resultDocumentInst) error {
	// Resolve parameter-document if specified as avt. Store the resolved
	// output def on execContext (not on the compiled instruction) to avoid
	// mutating the stylesheet's instruction tree.
	if inst.ParameterDocAVT != nil && inst.ParameterDocOutputDef == nil {
		if _, cached := ec.paramDocOutputDefs[inst]; !cached {
			pdHref, pdErr := inst.ParameterDocAVT.evaluate(ctx, ec.contextNode)
			if pdErr != nil {
				return pdErr
			}

			if pdHref != "" {
				outDef := &OutputDef{}
				baseURI := ec.effectiveStaticBaseURI()
				// runtime=true so the helper classifies a load/parse failure as
				// a dynamic error (FODC0002), never a static one. A failure must
				// not be silently dropped: the transformation has to fail so
				// callers can observe it, and an over-cap read keeps
				// [ErrResourceTooLarge] in the chain (matched via errors.Is)
				// while errors.Is(err, ErrStaticError) stays false.
				_, presence, loadErr := loadParameterDocumentFromFile(ctx, ec.inputParseOptions(), outDef, baseURI, pdHref, ec.retrieveDocumentReader, true, false, ec.resourceLimit())
				if loadErr != nil {
					return loadErr
				}

				if ec.paramDocOutputDefs == nil {
					ec.paramDocOutputDefs = make(map[*resultDocumentInst]*OutputDef)
				}

				ec.paramDocOutputDefs[inst] = outDef
				if ec.paramDocPresences == nil {
					ec.paramDocPresences = make(map[*resultDocumentInst]paramDocPresence)
				}

				ec.paramDocPresences[inst] = presence
			}
		}
	}

	return nil
}

func (ec *execContext) resolveResultItemSeparator(ctx context.Context, inst *resultDocumentInst, effectiveFormat string) (*string, error) {
	// Resolve effective item-separator: xsl:result-document attribute takes
	// priority (including #absent which blocks format inheritance),
	// then the named xsl:output (format), then nil (default).
	var itemSep *string

	if inst.ItemSeparatorSet {
		// Attribute was present on xsl:result-document; evaluate avt value
		// (nil for #absent, or the evaluated string).
		if inst.ItemSeparator != nil {
			sepVal, err := inst.ItemSeparator.evaluate(ctx, ec.contextNode)
			if err != nil {
				return nil, err
			}

			itemSep = &sepVal
		}
	} else if effectiveFormat != "" {
		if outDef, ok := ec.effectiveOutputs()[effectiveFormat]; ok && outDef.ItemSeparator != nil {
			itemSep = outDef.ItemSeparator
		}
	} else if outDef, ok := ec.effectiveOutputs()[""]; ok && outDef.ItemSeparator != nil {
		itemSep = outDef.ItemSeparator
	}

	return itemSep, nil
}

// execPrimaryResultDocument evaluates every serialization AVT before any body
// execution and publishes serialization state only after the chosen branch succeeds.
func (ec *execContext) execPrimaryResultDocument(ctx context.Context, inst *resultDocumentInst, effectiveFormat string, itemSep *string) error {
	primaryOverrides, err := ec.evalResultDocOutputDef(ctx, inst)
	if err != nil {
		return err
	}

	effectiveMethod := ec.resolveResultDocMethod(ctx, inst)
	validation := inst.Validation
	buildTreeNo := primaryOverrides != nil && primaryOverrides.BuildTree != nil && !*primaryOverrides.BuildTree

	switch {
	case inst.TypeName != "" && validation == "":
		err = ec.execPrimaryValidatedDocument(ctx, inst, effectiveMethod, itemSep, false)
	case validation == validationStrict || validation == validationLax:
		err = ec.execPrimaryValidatedDocument(ctx, inst, effectiveMethod, itemSep, validation == validationStrict)
	case buildTreeNo && isItemSerializationMethod(effectiveMethod):
		err = ec.execPrimaryItemDocument(ctx, inst, effectiveMethod, itemSep, primaryOverrides)
	default:
		err = ec.execPrimaryBufferedDocument(ctx, inst, effectiveMethod, itemSep, primaryOverrides)
	}

	if err != nil {
		return err
	}

	ec.commitPrimaryOutputState(inst, effectiveFormat, primaryOverrides)

	return nil
}

func (ec *execContext) executeResultDocFrame(ctx context.Context, body []instruction, frame *outputFrame, method string, primary bool) error {
	savedMethod := ec.currentResultDocMethod
	ec.currentResultDocMethod = method

	ec.outputStack = append(ec.outputStack, frame)
	if primary {
		ec.insideResultDocPrimary = true
	}

	err := ec.executeSequenceConstructor(ctx, body)
	if primary {
		ec.insideResultDocPrimary = false
	}

	ec.currentResultDocMethod = savedMethod
	ec.outputStack = ec.outputStack[:len(ec.outputStack)-1]

	return err
}

func (ec *execContext) execPrimaryValidatedDocument(ctx context.Context, inst *resultDocumentInst, method string, itemSep *string, strict bool) error {
	doc := xdm.NewDefaultDocument()

	frame := &outputFrame{doc: doc, current: doc, itemSeparator: itemSep}
	if err := ec.executeResultDocFrame(ctx, inst.Body, frame, method, false); err != nil {
		return err
	}

	if strict {
		if err := validateDocumentStructure(doc); err != nil {
			return err
		}
	}

	return moveChildren(doc, ec.outputStack[0].doc)
}

func (ec *execContext) validatePrimaryResultItems(items xdm.Sequence, method string, overrides *OutputDef) error {
	if method != methodJSON {
		return nil
	}

	allowDuplicates := false
	if overrides != nil {
		allowDuplicates = overrides.AllowDuplicateNames
	} else if def, ok := ec.effectiveOutputs()[""]; ok {
		allowDuplicates = def.AllowDuplicateNames
	}

	if !allowDuplicates {
		return validateJSONItems(items)
	}

	return nil
}

func (ec *execContext) execPrimaryItemDocument(ctx context.Context, inst *resultDocumentInst, effectiveMethod string, itemSep *string, primaryOverrides *OutputDef) error {
	tmpDoc := xdm.NewDefaultDocument()

	tmpRoot, err := tmpDoc.CreateElement("_tmp")
	if err != nil {
		return err
	}

	if err := tmpDoc.AddChild(tmpRoot); err != nil {
		return err
	}

	frame := &outputFrame{doc: tmpDoc, current: tmpRoot, itemSeparator: itemSep, captureItems: true, sequenceMode: true}
	if err := ec.executeResultDocFrame(ctx, inst.Body, frame, effectiveMethod, true); err != nil {
		return err
	}

	out := ec.outputStack[0]
	if err := ec.validatePrimaryResultItems(frame.pendingItems, effectiveMethod, primaryOverrides); err != nil {
		return err
	}

	out.pendingItems = append(out.pendingItems, frame.pendingItems...)

	return nil
}

func (ec *execContext) execPrimaryBufferedDocument(ctx context.Context, inst *resultDocumentInst, effectiveMethod string, itemSep *string, primaryOverrides *OutputDef) error {
	// Buffer the primary direct-write path: execute the body into a
	// temporary frame and splice it into the real primary output ONLY after
	// the body and all post-body checks succeed. A body that throws (e.g.
	// inside xsl:try) must leave NO partial primary output behind, so that
	// the deferred release of the "" reservation is sound and an xsl:catch
	// that writes another primary result document does not produce a
	// double-primary result.
	//
	// The buffer frame stands IN for the base frame: it temporarily replaces
	// ec.outputStack[0], and is never pushed on top, so that the body
	// observes the same outputStack depth (1) and the same insideResultDocPrimary
	// state as a true direct write. This keeps every depth-sensitive branch
	// (XTRE1495 suppression, rawResultSequence capture, etc.) behaving exactly
	// as before; only the destination tree changes, and only until commit.
	realBase := ec.outputStack[0]
	bufDoc := xdm.NewDefaultDocument()
	// Clone the REAL base frame so every output flag (captureItems,
	// sequenceMode, documentConstructor, mapConstructor, wherePopulated,
	// separateTextNodes, …) and accumulator (prevWasAtomic, prevHadOutput,
	// outputSerial, …) is preserved. If the real primary frame captures items
	// (raw delivery via cfg.rawCapture, or a json/adaptive default output
	// method), atomics from xsl:sequence MUST be preserved as XDM items, not
	// stringified into the DOM. Override ONLY the per-buffer destination
	// (doc/current), the per-buffer item-separator, and the per-buffer
	// accumulators that must start fresh for this buffer (pendingItems,
	// seqPlaceholders, conditionalScopes). Everything else carries over.
	bufFrameVal := *realBase
	bufFrame := &bufFrameVal
	bufFrame.doc = bufDoc
	bufFrame.current = bufDoc
	bufFrame.itemSeparator = itemSep
	bufFrame.pendingItems = nil
	bufFrame.seqPlaceholders = nil
	bufFrame.conditionalScopes = nil
	savedStack := ec.outputStack
	bufferedStack := make([]*outputFrame, len(ec.outputStack))
	copy(bufferedStack, ec.outputStack)
	bufferedStack[0] = bufFrame
	ec.outputStack = bufferedStack[:1] // keep only the (buffered) base frame
	ec.insideResultDocPrimary = true
	savedMethod := ec.currentResultDocMethod
	ec.currentResultDocMethod = effectiveMethod

	savedRawResult := ec.rawResultSequence
	if err := ec.executeSequenceConstructor(ctx, inst.Body); err != nil {
		ec.insideResultDocPrimary = false
		ec.currentResultDocMethod = savedMethod
		ec.rawResultSequence = savedRawResult
		ec.outputStack = savedStack

		return err
	}

	if err := ec.validatePrimaryResultItems(bufFrame.pendingItems, effectiveMethod, primaryOverrides); err != nil {
		ec.insideResultDocPrimary = false
		ec.currentResultDocMethod = savedMethod
		ec.rawResultSequence = savedRawResult
		ec.outputStack = savedStack

		return err
	}

	ec.insideResultDocPrimary = false
	ec.currentResultDocMethod = savedMethod
	ec.outputStack = savedStack
	// Body and all post-body checks succeeded: splice the buffered content
	// into the real primary output and propagate the accumulator state.
	if err := moveChildren(bufDoc, realBase.doc); err != nil {
		return err
	}

	realBase.pendingItems = append(realBase.pendingItems, bufFrame.pendingItems...)
	realBase.prevWasAtomic = bufFrame.prevWasAtomic
	realBase.prevHadOutput = bufFrame.prevHadOutput
	realBase.outputSerial = bufFrame.outputSerial
	realBase.emptyAtomicGen = bufFrame.emptyAtomicGen
	realBase.seqConstructorGen = bufFrame.seqConstructorGen
	// Commit the serialization overrides + character-map state. The overrides
	// were evaluated up front (before any primary output was emitted) so that
	// an AVT error releases the URI reservation without leaving partial primary
	// output behind.

	return nil
}

func (ec *execContext) execSecondaryResultDocument(ctx context.Context, inst *resultDocumentInst, effectiveFormat string, itemSep *string, href, dupKey string) error {
	// Secondary output: execute body into a temporary document.
	tmpDoc := xdm.NewDefaultDocument()

	// Set the document URL so that base-uri() returns the correct value. Per XSLT
	// 3.0 §26.2 a secondary result document's base URI is its href resolved
	// against the BASE OUTPUT URI, NOT the stylesheet base URI. ec.currentOutputURI
	// already holds exactly that value: it was set above (canonicalResultURIKey of
	// href against the saved base output URI) and is the same scheme-preserving
	// canonical URI used as the XTDE1490 duplicate-detection key.
	tmpDoc.SetURL(ec.currentOutputURI)

	// PREFLIGHT (symmetric with the primary path): evaluate the secondary
	// effective output definition — which evaluates EVERY error-prone
	// serialization parameter AVT (method, standalone, indent, doctype, etc.) via
	// evalResultDocOutputDef — BEFORE running the body. A serialization AVT that
	// raises a dynamic error (e.g. method="{1 idiv 0}") inside xsl:try must roll
	// the transaction back with NO body executed and NO per-href side effect: were
	// the AVTs evaluated AFTER the body (the prior order), a NESTED secondary
	// result-document inside the body could commit before the outer instruction's
	// AVT error surfaced, leaving the enclosing xsl:catch to observe a stale nested
	// result document. Building the output def up front guarantees any such error
	// happens before inst.Body executes.
	stagedOutDef, err := ec.buildEffectiveOutputDef(ctx, inst, effectiveFormat, "")
	if err != nil {
		return err
	}

	// Derive the effective output method from the preflighted output definition so
	// a MethodAVT error is NOT swallowed (resolveResultDocMethod silently ignores
	// MethodAVT failures): buildEffectiveOutputDef already surfaced any AVT error
	// above. Fall back to resolveResultDocMethod only for the non-AVT resolution
	// chain (static method, parameter-document, named format, default).
	effectiveMethod := stagedOutDef.Method
	if effectiveMethod == "" {
		effectiveMethod = ec.resolveResultDocMethod(ctx, inst)
		stagedOutDef.Method = effectiveMethod
		stagedOutDef.MethodExplicit = true
	}

	raw := ec.transformConfig != nil && ec.transformConfig.rawSequence

	frame := &outputFrame{doc: tmpDoc, current: tmpDoc, itemSeparator: itemSep, captureItems: isItemSerializationMethod(effectiveMethod) || raw, sequenceMode: raw}
	if err := ec.executeResultDocFrame(ctx, inst.Body, frame, effectiveMethod, false); err != nil {
		return err
	}

	// Stage ALL per-href state locally; publish into the shared evaluator maps
	// only at the single commit point below, after the body AND every post-body
	// validation step has succeeded. If a validation error is thrown here (and
	// possibly caught by an enclosing xsl:try), NO per-href side effect may
	// persist: a stale resultDocItems/resultDocOutputDefs entry would otherwise
	// be materialized at end-of-transform or contaminate an xsl:catch that writes
	// the same href (spurious XTDE1490 / wrong output). The three staged pieces
	// are: the captured json/adaptive items, the effective output definition (built
	// up front in the preflight above), and the result-document tree itself.
	var stagedItems xdm.Sequence
	if (isItemSerializationMethod(effectiveMethod) || raw) && len(frame.pendingItems) > 0 {
		stagedItems = frame.pendingItems
	}

	// Apply type validation for secondary result documents (type="...").

	// Validate the result document if requested.
	if v := inst.Validation; v == validationStrict || v == validationLax {
		// XTTE1550: when validating a document node, the children must comprise
		// exactly one element node, no text nodes, and zero or more comment and
		// processing instruction nodes, in any order.
		if v == validationStrict {
			if err := validateDocumentStructure(tmpDoc); err != nil {
				return err
			}
		}
	} else if inst.Validation == validationStrip {
		root := findDocumentElement(tmpDoc)
		if root != nil {
			ec.stripAnnotations(root)
		}
	}

	// SERE0022: a SECONDARY (href) JSON result document must reject duplicate
	// keys unless allow-duplicate-names="yes", exactly like the primary path. The
	// final SerializeItems pass in execute_transform.go does NOT re-validate
	// staged secondary items, so without this check a secondary
	// method="json" build-tree="no" result document would silently accept
	// map{1:'a','1':'b'}. Validate against the preflighted output definition
	// before committing so a thrown SERE0022 leaves no per-href side effect.
	if effectiveMethod == methodJSON && stagedItems != nil && !stagedOutDef.AllowDuplicateNames {
		if err := validateJSONItems(stagedItems); err != nil {
			return err
		}
	}

	// COMMIT POINT: body and every post-body validation step succeeded. Publish
	// all staged per-URI state atomically, then mark the transaction committed so
	// the deferred rollback leaves the usedResultURIs reservation in place. Storage
	// keys on the RESOLVED canonical absolute output URI (dupKey == tmpDoc.URL() ==
	// ec.currentOutputURI), NOT the raw href: two NESTED xsl:result-documents with
	// the same relative href under different enclosing output URIs resolve to
	// distinct absolute URIs and must not overwrite each other. The raw href is
	// preserved separately for the public ResultDocumentHandler.
	if stagedItems != nil {
		ec.resultDocItems[dupKey] = stagedItems
	}

	if stagedOutDef != nil {
		ec.resultDocOutputDefs[dupKey] = stagedOutDef
	}

	ec.resultDocuments[dupKey] = tmpDoc
	ec.resultDocHrefs[dupKey] = href

	return nil
}

// evalBoolSerializationAVT evaluates a boolean serialization-parameter AVT on
// xsl:result-document and returns its xs:boolean value. A non-empty value that
// is not a valid xs:boolean lexical form raises SEPM0016 instead of being
// silently coerced to false. This is the SINGLE chokepoint that EVERY boolean
// serialization parameter (indent, omit-xml-declaration, byte-order-mark,
// escape-uri-attributes, include-content-type, allow-duplicate-names) must route
// through, so the invalid-value validation can never drift parameter-by-parameter
// again. (standalone is a tri-state yes/no/omit value and is handled separately.)
func (ec *execContext) evalBoolSerializationAVT(ctx context.Context, a *avt, paramName string) (bool, error) {
	v, err := a.evaluate(ctx, ec.contextNode)
	if err != nil {
		return false, err
	}

	b, ok := parseXSDBool(strings.TrimSpace(v))
	if !ok {
		return false, dynamicError(errCodeSEPM0016,
			"%q is not a valid value for xsl:result-document/@%s", v, paramName)
	}

	return b, nil
}

// evalResultDocOutputDef evaluates serialization parameter AVTs on
// xsl:result-document and returns an OutputDef with the overrides.
// Returns nil if no serialization parameters are specified.
func (ec *execContext) evalResultDocOutputDef(ctx context.Context, inst *resultDocumentInst) (*OutputDef, error) {
	hasAny := inst.hasSerializationParameters(ec.getParamDocOutputDef(inst) != nil)

	effectiveFormat, err := ec.resolveResultDocFormat(ctx, inst)
	if err != nil {
		return nil, err
	}

	if !hasAny && effectiveFormat == "" {
		return nil, nil //nolint:nilnil
	}

	base := ec.resultDocOutputBase(inst, effectiveFormat)
	if err := ec.evalResultDocDeclarationParams(ctx, inst, &base); err != nil {
		return nil, err
	}

	if err := ec.evalResultDocMarkupParams(ctx, inst, &base); err != nil {
		return nil, err
	}

	if err := ec.evalResultDocItemParams(ctx, inst, &base); err != nil {
		return nil, err
	}

	return &base, nil
}

// resultDocOutputBase folds the named/default output and then only parameters
// explicitly provided by a parameter-document, preserving inherited booleans.
func (ec *execContext) resultDocOutputBase(inst *resultDocumentInst, effectiveFormat string) OutputDef {
	var base OutputDef

	paramDocOD := ec.getParamDocOutputDef(inst)
	if effectiveFormat != "" {
		if fmtDef, ok := ec.effectiveOutputs()[effectiveFormat]; ok {
			base = *cloneOutputDef(fmtDef)
		}
	} else if defDef, ok := ec.effectiveOutputs()[""]; ok {
		base = *cloneOutputDef(defDef)
	}

	if paramDocOD != nil {
		foldParamDocOverrides(&base, paramDocOD, ec.getParamDocPresence(inst))
	}

	return base
}

// foldParamDocOverrides overlays the serialization parameters supplied by a
// result-document's parameter-document (pd, loaded as a delta from an empty
// OutputDef) onto base, which already holds the inherited named-format or
// unnamed-default xsl:output values. A parameter-document outranks the format it
// layers on, so any value it specifies wins; values it OMITS leave base intact.
// String/pointer/slice fields are absent when zero/nil/empty; the plain-boolean
// parameters rely on the companion paramDocPresence flags because a false bool
// cannot otherwise be distinguished from an omitted one.
func foldParamDocOverrides(base, pd *OutputDef, pres paramDocPresence) {
	if pd.Method != "" {
		base.Method = pd.Method
		base.MethodExplicit = pd.MethodExplicit
	}

	if pd.Encoding != "" {
		base.Encoding = pd.Encoding
	}

	if pd.Standalone != "" {
		base.Standalone = pd.Standalone
	}

	if len(pd.CDATASections) > 0 {
		base.CDATASections = append([]string(nil), pd.CDATASections...)
	}

	if pd.DoctypePublic != "" {
		base.DoctypePublic = pd.DoctypePublic
	}

	if pd.DoctypeSystem != "" {
		base.DoctypeSystem = pd.DoctypeSystem
	}

	if pd.MediaType != "" {
		base.MediaType = pd.MediaType
	}

	if pd.Version != "" {
		base.Version = pd.Version
	}

	if pd.NormalizationForm != "" {
		base.NormalizationForm = pd.NormalizationForm
	}

	if pd.HTMLVersion != "" {
		base.HTMLVersion = pd.HTMLVersion
	}

	if pd.JSONNodeOutputMethod != "" {
		base.JSONNodeOutputMethod = pd.JSONNodeOutputMethod
	}

	if len(pd.SuppressIndentation) > 0 {
		base.SuppressIndentation = append([]string(nil), pd.SuppressIndentation...)
	}

	if pd.IncludeContentType != nil {
		v := *pd.IncludeContentType
		base.IncludeContentType = &v
	}

	if pd.EscapeURIAttributes != nil {
		v := *pd.EscapeURIAttributes
		base.EscapeURIAttributes = &v
	}

	if pd.BuildTree != nil {
		v := *pd.BuildTree
		base.BuildTree = &v
	}

	if pd.ItemSeparator != nil {
		v := *pd.ItemSeparator
		base.ItemSeparator = &v
	}

	if len(pd.ResolvedCharMap) > 0 {
		base.ResolvedCharMap = make(map[rune]string, len(pd.ResolvedCharMap))
		maps.Copy(base.ResolvedCharMap, pd.ResolvedCharMap)
	}

	if pd.OmitDeclarationExplicit {
		base.OmitDeclaration = pd.OmitDeclaration
		base.OmitDeclarationExplicit = true
	}

	if pres.indent {
		base.Indent = pd.Indent
	}

	if pres.byteOrderMark {
		base.ByteOrderMark = pd.ByteOrderMark
	}

	if pres.allowDuplicateNames {
		base.AllowDuplicateNames = pd.AllowDuplicateNames
	}

	if pres.undeclarePrefixes {
		base.UndeclarePrefixes = pd.UndeclarePrefixes
	}
}

func (ec *execContext) evalSerializationAVT(ctx context.Context, value *avt) (string, error) {
	if value == nil {
		return "", nil
	}

	return value.evaluate(ctx, ec.contextNode)
}

func (ec *execContext) evalResultDocDeclarationParams(ctx context.Context, inst *resultDocumentInst, base *OutputDef) error {
	if inst.MethodAVT != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.MethodAVT)
		if err != nil {
			return err
		}

		base.Method = strings.TrimSpace(v)
		base.MethodExplicit = true
	}

	if inst.Standalone != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.Standalone)
		if err != nil {
			return err
		}

		switch strings.TrimSpace(v) {
		case lexicon.ValueTrue, "1":
			v = lexicon.ValueYes
		case nameFalse, "0":
			v = lexicon.ValueNo
		default:
			v = strings.TrimSpace(v)
		}

		base.Standalone = v
	}

	if inst.Indent != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.Indent, paramIndent)
		if err != nil {
			return err
		}

		base.Indent = b
	}

	if inst.OmitXMLDeclaration != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.OmitXMLDeclaration, paramOmitXMLDeclaration)
		if err != nil {
			return err
		}

		base.OmitDeclaration = b
		// The result-document explicitly specified omit-xml-declaration, so the
		// xhtml/html5 serializer must not flip it back to "yes" by default.
		base.OmitDeclarationExplicit = true
	}

	if inst.DoctypeSystem != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.DoctypeSystem)
		if err != nil {
			return err
		}

		base.DoctypeSystem = v
	}

	if inst.DoctypePublic != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.DoctypePublic)
		if err != nil {
			return err
		}

		base.DoctypePublic = v
	}

	if inst.Encoding != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.Encoding)
		if err != nil {
			return err
		}

		base.Encoding = strings.TrimSpace(v)
	}

	if inst.OutputVersion != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.OutputVersion)
		if err != nil {
			return err
		}

		base.Version = strings.TrimSpace(v)
	}

	return nil
}

func (ec *execContext) evalResultDocMarkupParams(ctx context.Context, inst *resultDocumentInst, base *OutputDef) error {
	if inst.ByteOrderMark != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.ByteOrderMark, paramByteOrderMark)
		if err != nil {
			return err
		}

		base.ByteOrderMark = b
	}

	if inst.CDATASectionElements != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.CDATASectionElements)
		if err != nil {
			return err
		}

		if v = strings.TrimSpace(v); v != "" {
			// Union with base cdata-section-elements from xsl:output.
			existing := make(map[string]struct{}, len(base.CDATASections))
			for _, name := range base.CDATASections {
				existing[name] = struct{}{}
			}

			for name := range strings.FieldsSeq(v) {
				resolved := resolveQName(name, inst.NSBindings)
				if _, ok := existing[resolved]; !ok {
					base.CDATASections = append(base.CDATASections, resolved)
				}
			}
		}
	}

	if inst.MediaType != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.MediaType)
		if err != nil {
			return err
		}

		base.MediaType = strings.TrimSpace(v)
	}

	if inst.HTMLVersion != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.HTMLVersion)
		if err != nil {
			return err
		}

		base.HTMLVersion = strings.TrimSpace(v)
	}

	if inst.IncludeContentType != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.IncludeContentType, paramIncludeContentType)
		if err != nil {
			return err
		}

		base.IncludeContentType = &b
	}

	return nil
}

func (ec *execContext) evalResultDocItemParams(ctx context.Context, inst *resultDocumentInst, base *OutputDef) error {
	if inst.AllowDuplicateNames != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.AllowDuplicateNames, paramAllowDuplicateNames)
		if err != nil {
			return err
		}

		base.AllowDuplicateNames = b
	}

	if inst.UndeclarePrefixes != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.UndeclarePrefixes, paramUndeclarePrefixes)
		if err != nil {
			return err
		}

		base.UndeclarePrefixes = b
	}

	if inst.EscapeURIAttributes != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.EscapeURIAttributes, paramEscapeURIAttributes)
		if err != nil {
			return err
		}

		base.EscapeURIAttributes = &b
	}

	if inst.JSONNodeOutputMethodAVT != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.JSONNodeOutputMethodAVT)
		if err != nil {
			return err
		}

		base.JSONNodeOutputMethod = strings.TrimSpace(v)
	}

	if inst.NormalizationForm != nil {
		v, err := ec.evalSerializationAVT(ctx, inst.NormalizationForm)
		if err != nil {
			return err
		}

		base.NormalizationForm = strings.ToUpper(strings.TrimSpace(v))
	}

	if len(inst.SuppressIndentation) > 0 {
		// Copy the slice so a derived/handler-delivered OutputDef cannot mutate
		// the compiled instruction's SuppressIndentation backing array.
		base.SuppressIndentation = append([]string(nil), inst.SuppressIndentation...)
	}

	if inst.ItemSeparatorSet {
		if inst.ItemSeparator != nil {
			sepVal, err := inst.ItemSeparator.evaluate(ctx, ec.contextNode)
			if err != nil {
				return err
			}

			base.ItemSeparator = &sepVal
		} else {
			base.ItemSeparator = nil
			base.ItemSeparatorAbsent = true
		}
	}

	if inst.BuildTree != nil {
		b, err := ec.evalBoolSerializationAVT(ctx, inst.BuildTree, paramBuildTree)
		if err != nil {
			return err
		}

		base.BuildTree = &b
	}

	return nil
}

// buildEffectiveOutputDef builds the effective output definition for a secondary
// result document, combining the named format with result-document overrides.
func (ec *execContext) buildEffectiveOutputDef(ctx context.Context, inst *resultDocumentInst, formatName, method string) (*OutputDef, error) {
	// Build the base in priority order (low -> high): named format (or the
	// unnamed default xsl:output when no format), then the parameter-document.
	// This mirrors evalResultDocOutputDef's default-folding; without the default
	// fold a secondary result-document with no local serialization attributes
	// would not inherit stylesheet defaults (e.g. method="json"
	// allow-duplicate-names="yes"), and the SERE0022 dup-key check below would see
	// a hard-false allow-duplicate-names and wrongly reject duplicate JSON keys
	// the default output permits. When evalResultDocOutputDef returns a non-nil
	// overrides def (hasAny or a named format), it already folded the default and
	// the parameter-document in and base is replaced below; this construction only
	// matters when overrides is nil (no serialization params and no
	// parameter-document, hence paramDocOD is nil here too).
	base := ec.resultDocOutputBase(inst, formatName)

	if base.Method == "" && method != "" {
		base.Method = method
		base.MethodExplicit = true
	}
	// Apply overrides from xsl:result-document.
	// evalResultDocOutputDef already starts from the named format base and
	// applies all xsl:result-document attribute overrides, so use it as the
	// complete effective output def when available.
	overrides, err := ec.evalResultDocOutputDef(ctx, inst)
	if err != nil {
		return nil, err
	}

	if overrides != nil {
		base = *cloneOutputDef(overrides)
	}
	// Resolve character maps from the format and instruction.
	var allMaps []string

	if formatName != "" {
		if fmtDef, ok := ec.effectiveOutputs()[formatName]; ok {
			allMaps = append(allMaps, fmtDef.UseCharacterMaps...)
		}
	}

	allMaps = append(allMaps, inst.UseCharacterMaps...)
	if len(allMaps) > 0 {
		base.ResolvedCharMap = resolveCharacterMaps(ec.effectiveStylesheet(), allMaps)
	}

	return &base, nil
}

// validateDocumentStructure checks that a document node has exactly one element
// child, no text nodes (non-whitespace), and only comments/PIs otherwise.
// Returns XTTE1550 on violation.
func validateDocumentStructure(doc *xdm.Document) error {
	elemCount := 0

	for child := range xdm.Children(doc) {
		switch child.Type() {
		case xdm.ElementNode:
			elemCount++
		case xdm.TextNode, xdm.CDATASectionNode:
			// Any text content at the document level (including whitespace
			// that is not whitespace-only) fails validation.
			text := xdm.CharacterData(child)
			if !isXMLWhitespaceOnly(text) {
				return dynamicError(errCodeXTTE1550,
					"validated document has text nodes at the top level")
			}
		case xdm.CommentNode, xdm.ProcessingInstructionNode:
			// Allowed at document level.
		}
	}

	if elemCount != 1 {
		return dynamicError(errCodeXTTE1550,
			"validated document must have exactly one root element, found %d", elemCount)
	}

	return nil
}

// moveChildren transfers every child of src into dst, preserving order. Each
// child is unlinked from src before being added to dst so that the source
// document's sibling/parent links do not remain attached to the moved nodes
// (which would alias nodes across two trees and can corrupt sibling traversal).
func moveChildren(src *xdm.Document, dst *xdm.Document) error {
	var children []xdm.Node
	for child := range xdm.Children(src) {
		children = append(children, child)
	}

	for _, child := range children {
		xdm.UnlinkNode(child.(xdm.MutableNode)) //nolint:forcetypeassert

		if err := dst.AddChild(child); err != nil {
			return err
		}
	}

	return nil
}

// validateJSONItems checks for SERE0022 (duplicate keys) in JSON-serializable items.
func validateJSONItems(items xdm.Sequence) error {
	for item := range xdm.SequenceItems(items) {
		if m, ok := item.(xdm.MapItem); ok {
			if err := validateMapDuplicateKeys(m); err != nil {
				return err
			}
		}

		if a, ok := item.(xdm.ArrayItem); ok {
			for _, member := range a.Members() {
				if err := validateJSONItems(member); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateMapDuplicateKeys checks a map for keys that produce the same
// string representation, which is a SERE0022 error in JSON serialization.
func validateMapDuplicateKeys(m xdm.MapItem) error {
	seenKeys := make(map[string]struct{})

	var dupErr error

	_ = m.ForEach(func(k xdm.AtomicValue, v xdm.Sequence) error {
		if dupErr != nil {
			return dupErr
		}

		ks, _ := xpath.AtomicToString(k)
		if _, dup := seenKeys[ks]; dup {
			dupErr = dynamicError(errCodeSERE0022, "duplicate key %q in JSON output", ks)
			return dupErr
		}

		seenKeys[ks] = struct{}{}
		// Recursively check nested maps/arrays.
		if err := validateJSONItems(v); err != nil {
			dupErr = err
			return err
		}

		return nil
	})

	return dupErr
}

// isItemSerializationMethod returns true when the output method supports
// non-node items (maps, arrays, function items) without XTDE0450.
func isItemSerializationMethod(method string) bool {
	return method == methodJSON || method == methodAdaptive
}

func (inst *resultDocumentInst) hasSerializationParameters(parameterDocument bool) bool {
	return inst.MethodAVT != nil || inst.Standalone != nil || inst.Indent != nil ||
		inst.OmitXMLDeclaration != nil || inst.DoctypeSystem != nil || inst.DoctypePublic != nil ||
		inst.CDATASectionElements != nil || inst.Encoding != nil || inst.OutputVersion != nil ||
		inst.ByteOrderMark != nil || inst.EscapeURIAttributes != nil ||
		inst.MediaType != nil || inst.HTMLVersion != nil || inst.IncludeContentType != nil ||
		inst.AllowDuplicateNames != nil || inst.UndeclarePrefixes != nil ||
		inst.JSONNodeOutputMethodAVT != nil || inst.NormalizationForm != nil ||
		parameterDocument ||
		inst.ItemSeparatorSet || inst.BuildTree != nil ||
		len(inst.SuppressIndentation) > 0
}
