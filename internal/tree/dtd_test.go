package tree_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	"github.com/skarm/xmlsec/internal/tree"
)

func TestParseDTDReaderDecodesAndNormalizesPhysicalEntity(t *testing.T) {
	t.Parallel()

	const xml = "<?xml version='1.0' encoding='UTF-16'?><!DOCTYPE r><r>é\r\nβ\r終&#13;</r>"
	units := utf16.Encode([]rune(xml))
	encoded := make([]byte, 0, 2+2*len(units))
	encoded = append(encoded, 0xff, 0xfe)
	for _, unit := range units {
		encoded = append(encoded, byte(unit), byte(unit>>8))
	}
	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
	doc, err := options.ParseReader(t.Context(), iotest.OneByteReader(bytes.NewReader(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := doc.Root().Text(), "é\nβ\n終\r"; got != want {
		t.Errorf("root text = %q, want %q", got, want)
	}
	if dtd, ok := doc.DTD(); !ok || dtd.Name != "r" {
		t.Errorf("document type = %+v, %v, want r", dtd, ok)
	}
}

func TestParseDTDReaderLoadsConditionalDeclarations(t *testing.T) {
	t.Parallel()

	const subset = `<?xml encoding="UTF-8"?>
		<![INCLUDE[
			<!ELEMENT r EMPTY>
			<!ATTLIST r label CDATA "catalog">
			<?index ready ?>
			<![IGNORE[<!ATTLIST r ignored CDATA "pass"> <![nested]]>]]>
			<!NOTATION png SYSTEM "image/png">
		]]>`
	const base, subsetBase = "urn:example:document", "urn:example:subset"
	var calls int
	stream := &dtdReaderFixture{Reader: iotest.OneByteReader(strings.NewReader(subset))}
	options := tree.ParseOptions{
		Limits:   tree.DefaultLimits(),
		AllowDTD: true,
		BaseURI:  base,
		DTDResolver: func(_ context.Context, systemID, retrievalBase string) (io.ReadCloser, string, error) {
			calls++
			if systemID != "catalog.dtd" || retrievalBase != base {
				t.Errorf("resolver identifiers = %q, %q, want catalog.dtd and %q", systemID, retrievalBase, base)
			}
			return stream, subsetBase, nil
		},
	}
	const input = `<!DOCTYPE r PUBLIC " -//Example   Catalog//EN " "catalog.dtd"><r/>`
	doc, err := options.ParseReader(t.Context(), iotest.OneByteReader(strings.NewReader(input)))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || stream.closed != 1 {
		t.Errorf("resolver calls = %d, closes = %d, want one of each", calls, stream.closed)
	}
	wantAttrs := []tree.Attribute{{Name: tree.Name{Local: "label"}, Value: "catalog"}}
	if got := tree.Root(doc).Attrs; !slices.Equal(got, wantAttrs) {
		t.Errorf("root attributes = %+v, want %+v", got, wantAttrs)
	}
	dtd, ok := doc.DTD()
	if !ok || dtd.SystemID != "catalog.dtd" || dtd.PublicID != "-//Example Catalog//EN" {
		t.Fatalf("DTD = %+v, %v, want normalized public and system identifiers", dtd, ok)
	}
	wantNotation := tree.Notation{SystemID: "image/png", BaseURI: subsetBase}
	if got := dtd.Notations["png"]; got != wantNotation {
		t.Errorf("png notation = %+v, want %+v", got, wantNotation)
	}
	wantInstructions := []tree.ProcessingInstruction{{Target: "index", Data: "ready ", BaseURI: subsetBase}}
	if !slices.Equal(dtd.ProcessingInstructions, wantInstructions) {
		t.Errorf("DTD instructions = %+v, want %+v", dtd.ProcessingInstructions, wantInstructions)
	}
}

func TestParseDTDReaderChecksSubsetResultAndClosesStream(t *testing.T) {
	t.Parallel()

	readErr := errors.New("fixture read failure")
	closeErr := errors.New("fixture close failure")
	for _, tc := range []struct {
		name    string
		source  func() io.Reader
		onClose error
		want    error
	}{
		{"invalid-conditional-keyword", func() io.Reader { return strings.NewReader(`<![UNKNOWN[<!ELEMENT r EMPTY>]]>`) }, nil, tree.ErrMalformed},
		{"unterminated-ignore", func() io.Reader { return strings.NewReader(`<![IGNORE[unused`) }, nil, tree.ErrMalformed},
		{"text-declaration-missing-encoding", func() io.Reader { return strings.NewReader(`<?xml version="1.0"?><!ELEMENT r EMPTY>`) }, nil, tree.ErrMalformed},
		{"text-declaration-with-standalone", func() io.Reader {
			return strings.NewReader(`<?xml encoding="UTF-8" standalone="yes"?><!ELEMENT r EMPTY>`)
		}, nil, tree.ErrMalformed},
		{"reader-failure", func() io.Reader { return iotest.ErrReader(readErr) }, closeErr, readErr},
		{"close-failure", func() io.Reader { return strings.NewReader(`<!ELEMENT r EMPTY>`) }, closeErr, closeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stream := &dtdReaderFixture{Reader: tc.source(), closeErr: tc.onClose}
			options := tree.ParseOptions{
				Limits: tree.DefaultLimits(), AllowDTD: true,
				DTDResolver: func(context.Context, string, string) (io.ReadCloser, string, error) {
					return stream, "urn:example:subset", nil
				},
			}
			doc, err := options.ParseReader(t.Context(), strings.NewReader(`<!DOCTYPE r SYSTEM "catalog.dtd"><r/>`))
			if doc != nil || !errors.Is(err, tc.want) {
				t.Errorf("ParseReader result = %v, %v, want nil document and %v", doc, err, tc.want)
			}
			if tc.onClose != nil && !errors.Is(err, tc.onClose) {
				t.Errorf("ParseReader error = %v, want close error %v", err, tc.onClose)
			}
			if stream.closed != 1 {
				t.Errorf("stream closes = %d, want 1", stream.closed)
			}
		})
	}
}

func TestParseDTDReaderBoundsExternalSubsetByRemainingInput(t *testing.T) {
	t.Parallel()

	// UTF-8 BOM and CRLF contribute to the physical input size even though the
	// parser discards the BOM and normalizes the line endings before expansion.
	const input = "\ufeff<!DOCTYPE r SYSTEM 'catalog.dtd'>\r\n<r/>"
	const subset = `<!ELEMENT r EMPTY>`
	for _, tc := range []struct {
		name      string
		subset    string
		remaining int
		wantRead  int
		wantErr   error
	}{
		{"exact", subset, len(subset), len(subset), nil},
		{"exhausted-empty", "", 0, 0, nil},
		{"above-limit", subset + strings.Repeat(" ", 128), len(subset), len(subset) + 1, tree.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reader := strings.NewReader(tc.subset)
			stream := &dtdReaderFixture{Reader: reader}
			options := tree.ParseOptions{
				Limits: tree.DefaultLimits(), AllowDTD: true,
				DTDResolver: func(context.Context, string, string) (io.ReadCloser, string, error) {
					return stream, "urn:example:subset", nil
				},
			}
			options.Limits.MaxBytes = len(input) + tc.remaining
			doc, err := options.ParseReader(t.Context(), strings.NewReader(input))
			if !errors.Is(err, tc.wantErr) || (doc == nil) != (tc.wantErr != nil) {
				t.Errorf("ParseReader = (%v, %v), want error %v", doc, err, tc.wantErr)
			}
			if got := len(tc.subset) - reader.Len(); got != tc.wantRead || stream.closed != 1 {
				t.Errorf("external bytes read = %d, closes = %d, want %d bytes and one close", got, stream.closed, tc.wantRead)
			}
		})
	}
}

func TestParseDTDReaderPreservesResolverErrors(t *testing.T) {
	t.Parallel()

	const input = `<!DOCTYPE catalog SYSTEM "catalog.dtd"><catalog/>`
	resolveErr := errors.New("catalog lookup failed")
	closeErr := errors.New("catalog stream close failed")
	for _, tc := range []struct {
		name      string
		stream    func(*dtdReaderFixture) io.ReadCloser
		resolve   error
		want      error
		wantClose int
	}{
		{"lookup-failure", func(*dtdReaderFixture) io.ReadCloser { return nil }, resolveErr, resolveErr, 0},
		{"lookup-failure-with-stream", func(r *dtdReaderFixture) io.ReadCloser { return r }, resolveErr, resolveErr, 1},
		{"nil-stream", func(*dtdReaderFixture) io.ReadCloser { return (*dtdReaderFixture)(nil) }, nil, tree.ErrMalformed, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stream := &dtdReaderFixture{Reader: strings.NewReader(`<!ELEMENT catalog EMPTY>`), closeErr: closeErr}
			options := tree.ParseOptions{
				Limits: tree.DefaultLimits(), AllowDTD: true,
				DTDResolver: func(context.Context, string, string) (io.ReadCloser, string, error) {
					return tc.stream(stream), "urn:example:catalog", tc.resolve
				},
			}
			doc, err := options.ParseReader(t.Context(), strings.NewReader(input))
			if doc != nil || !errors.Is(err, tc.want) {
				t.Errorf("ParseReader = %v, %v, want nil document and %v", doc, err, tc.want)
			}
			if tc.wantClose > 0 && !errors.Is(err, closeErr) {
				t.Errorf("ParseReader error = %v, want close error %v", err, closeErr)
			}
			if stream.closed != tc.wantClose {
				t.Errorf("stream closes = %d, want %d", stream.closed, tc.wantClose)
			}
		})
	}
}

func TestParseDTDReaderResolvesParameterDeclarations(t *testing.T) {
	t.Parallel()

	const documentBase = "urn:example:catalog"
	const subsetBase = "urn:example:catalog-subset"
	const textBase = "urn:example:label-source"
	const input = `<!DOCTYPE catalog SYSTEM "catalog.dtd"><catalog>&label;</catalog>`
	const subset = `<!ENTITY % shape "(entry+)">
		<!ELEMENT catalog %shape;>
		<!ELEMENT entry (#PCDATA)>
		<!ENTITY % text SYSTEM "label.ent">
		<!ENTITY label "[%text;]">
		<!ATTLIST catalog name CDATA "&label;">`
	streams := map[string]*dtdReaderFixture{
		"catalog.dtd": {Reader: strings.NewReader(subset)},
		"label.ent":   {Reader: strings.NewReader("<?xml encoding='UTF-8'?>catalogue")},
	}
	options := tree.ParseOptions{
		Limits: tree.DefaultLimits(), AllowDTD: true, BaseURI: documentBase,
		DTDResolver: func(_ context.Context, systemID, base string) (io.ReadCloser, string, error) {
			switch {
			case systemID == "catalog.dtd" && base == documentBase:
				return streams[systemID], subsetBase, nil
			case systemID == "label.ent" && base == subsetBase:
				return streams[systemID], textBase, nil
			default:
				t.Fatalf("unexpected fixture lookup: %q relative to %q", systemID, base)
				return nil, "", tree.ErrMalformed
			}
		},
	}
	doc, err := options.ParseReader(t.Context(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	const want = "[catalogue]"
	if got := doc.Root().Text(); got != want {
		t.Errorf("catalog text = %q, want %q", got, want)
	}
	if got, ok := doc.Root().Attribute(tree.Name{Local: "name"}); !ok || got != want {
		t.Errorf("catalog name = %q, %t, want %q", got, ok, want)
	}
	for systemID, stream := range streams {
		if stream.closed != 1 {
			t.Errorf("%s stream closes = %d, want 1", systemID, stream.closed)
		}
	}
}

func TestParseDTDReaderRetainsQualifiedTypesAndEntityOrigin(t *testing.T) {
	t.Parallel()

	const docBase, entityBase = "urn:example:document", "urn:example:row"
	const input = `<!DOCTYPE p:rows [
		<!ENTITY row SYSTEM "row.xml">
		<!ATTLIST p:row p:key ID #REQUIRED p:next IDREF #IMPLIED>
	]><p:rows xmlns:p="urn:example:data">&row;&row;</p:rows>`
	const entity = `<?xml encoding="UTF-8"?><?source row ?><p:row p:key=" row " p:next=" other "><?cell ready ?></p:row>`
	stream := &dtdReaderFixture{Reader: strings.NewReader(entity)}
	calls := 0
	options := tree.ParseOptions{
		Limits: tree.DefaultLimits(), AllowDTD: true, BaseURI: docBase,
		DTDResolver: func(_ context.Context, systemID, base string) (io.ReadCloser, string, error) {
			calls++
			if systemID != "row.xml" || base != docBase {
				t.Fatalf("resolver identifiers = %q, %q, want row.xml and %q", systemID, base, docBase)
			}
			return stream, entityBase, nil
		},
	}
	doc, err := options.ParseReader(t.Context(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	children := tree.Root(doc).Children
	if len(children) != 4 || children[1] == children[3] {
		t.Fatalf("root children = %v, want two distinct rows each preceded by a processing instruction", children)
	}
	for i := 0; i < len(children); i += 2 {
		pi, row := children[i], children[i+1]
		if got := tree.NodeBase(doc, row); got != entityBase || row.Name != (tree.Name{Space: "urn:example:data", Local: "row"}) {
			t.Errorf("child %d name = %v, base = %q, want namespaced row from %q", i+1, row.Name, got, entityBase)
		}
		attrs := make(map[string]string, len(row.Attrs))
		for _, attr := range row.Attrs {
			attrs[attr.Name.Local] = attr.Value
		}
		want := map[string]string{"key": "row", "next": "other"}
		if !maps.Equal(attrs, want) {
			t.Errorf("child %d attributes = %v, want %v", i+1, attrs, want)
		}
		for local, want := range map[string]tree.DTDAttributeType{"key": tree.DTDID, "next": tree.DTDIDRef} {
			if got := tree.AttributeDTDType(doc, row, tree.Name{Space: "urn:example:data", Local: local}); got != want {
				t.Errorf("child %d DTD type of %s = %v, want %v", i+1, local, got, want)
			}
		}
		if len(row.Children) != 1 {
			t.Fatalf("child %d children = %v, want a processing instruction", i+1, row.Children)
		}
		if got := tree.NodeBase(doc, pi); got != entityBase || pi.Kind != tree.PINode || pi.Name.Local != "source" || pi.Data != "row " {
			t.Errorf("child %d processing instruction = %+v, base = %q, want source with row data from %q", i, pi, got, entityBase)
		}
		cell := row.Children[0]
		if got := tree.NodeBase(doc, cell); got != "" || cell.Kind != tree.PINode || cell.Name.Local != "cell" || cell.Data != "ready " || cell.Parent != row {
			t.Errorf("nested processing instruction = %+v, base override = %q, want cell to inherit its row's base", cell, got)
		}
	}
	if calls != 1 || stream.closed != 1 {
		t.Errorf("entity resolver calls = %d, stream closes = %d, want one of each", calls, stream.closed)
	}
}

type dtdReaderFixture struct {
	io.Reader
	closeErr error
	closed   int
}

func (r *dtdReaderFixture) Close() error {
	r.closed++
	return r.closeErr
}

func TestParseDTDTextPreservesTypedAttributeDefaults(t *testing.T) {
	t.Parallel()

	const input = `<!DOCTYPE catalog [
		<!ELEMENT catalog (#PCDATA|entry)*>
		<!ELEMENT entry EMPTY>
		<!NOTATION png SYSTEM "image/png">
		<!NOTATION svg PUBLIC "  -//Example   SVG//EN  ">
		<!ENTITY logo SYSTEM "logo.svg" NDATA svg>
		<!ATTLIST catalog id ID #REQUIRED
			primary IDREF #IMPLIED related IDREFS #IMPLIED
			mode ( full | summary ) 'full'
			format NOTATION ( png | svg ) #FIXED 'svg'
			raw CDATA ' a  b ' note CDATA #IMPLIED>
		<!ATTLIST catalog mode ( full | summary ) 'summary'>
	]><catalog id=" item " primary=" first " related=" first  second " note="quote: &quot;&apos;" />`
	const base = "urn:catalog:example"
	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true, BaseURI: base}

	doc, err := options.ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root(doc)
	attrs := make(map[string]string, len(root.Attrs))
	for _, attr := range root.Attrs {
		attrs[attr.Name.Local] = attr.Value
	}
	want := map[string]string{
		"id": "item", "primary": "first", "related": "first second",
		"mode": "full", "format": "svg", "raw": " a  b ", "note": "quote: \"'",
	}
	if !maps.Equal(attrs, want) {
		t.Errorf("catalog attributes = %q, want %q", attrs, want)
	}
	for name, kind := range map[string]tree.DTDAttributeType{
		"id": tree.DTDID, "primary": tree.DTDIDRef, "related": tree.DTDIDRefs,
		"mode": tree.DTDNoType, "format": tree.DTDNoType,
	} {
		if got := tree.AttributeDTDType(doc, root, tree.Name{Local: name}); got != kind {
			t.Errorf("DTD type of %s = %v, want %v", name, got, kind)
		}
	}
	dtd, ok := doc.DTD()
	if !ok || dtd.Name != "catalog" {
		t.Fatalf("document type = %+v, %v, want catalog", dtd, ok)
	}
	wantNotations := map[string]tree.Notation{
		"png": {SystemID: "image/png", BaseURI: base},
		"svg": {PublicID: "-//Example SVG//EN", BaseURI: base},
	}
	if !maps.Equal(dtd.Notations, wantNotations) {
		t.Errorf("notations = %+v, want %+v", dtd.Notations, wantNotations)
	}
	wantEntities := map[string]tree.UnparsedEntity{
		"logo": {SystemID: "logo.svg", BaseURI: base, Notation: "svg"},
	}
	if !maps.Equal(dtd.UnparsedEntities, wantEntities) {
		t.Errorf("unparsed entities = %+v, want %+v", dtd.UnparsedEntities, wantEntities)
	}
}

func TestParseDTDTextPreservesDocumentAndDeclarationNodes(t *testing.T) {
	t.Parallel()

	const input = "\uFEFF<?xml version='1.7' standalone='yes'?>\r\n" +
		"<?before ready ?>\r<!DOCTYPE r [<?directory catalog ?>]><r>" +
		"<!--note\r\ncontinued--><![CDATA[a & <]]>&#13;<?within done ?></r><?after finish ?>"
	const base = "urn:xml:input"
	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true, BaseURI: base}

	doc, err := options.ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	type nodeValue struct {
		kind tree.Kind
		name string
		text string
	}
	values := func(nodes []*tree.Node) []nodeValue {
		list := make([]nodeValue, 0, len(nodes))
		for _, node := range nodes {
			list = append(list, nodeValue{node.Kind, node.Name.Local, node.Data})
		}
		return list
	}
	wantTop := []nodeValue{
		{tree.PINode, "before", "ready "},
		{tree.ElementNode, "r", ""},
		{tree.PINode, "after", "finish "},
	}
	if got := values(tree.Children(doc)); !slices.Equal(got, wantTop) {
		t.Errorf("document children = %#v, want %#v", got, wantTop)
	}
	wantChildren := []nodeValue{
		{tree.CommentNode, "", "note\ncontinued"},
		{tree.TextNode, "", "a & <\r"},
		{tree.PINode, "within", "done "},
	}
	if got := values(tree.Root(doc).Children); !slices.Equal(got, wantChildren) {
		t.Errorf("root children = %#v, want %#v", got, wantChildren)
	}
	dtd, ok := doc.DTD()
	wantInstructions := []tree.ProcessingInstruction{{Target: "directory", Data: "catalog ", BaseURI: base}}
	if !ok || !slices.Equal(dtd.ProcessingInstructions, wantInstructions) {
		t.Errorf("DTD instructions = %+v, %v, want %+v", dtd.ProcessingInstructions, ok, wantInstructions)
	}
}

func TestParseDTDTextRejectsMalformedDeclarations(t *testing.T) {
	t.Parallel()

	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
	for _, tc := range []struct{ name, input string }{
		{"empty-enumeration", `<!DOCTYPE r [<!ATTLIST r mode () #IMPLIED>]><r/>`},
		{"missing-enumeration-token", `<!DOCTYPE r [<!ATTLIST r mode (full|) #IMPLIED>]><r/>`},
		{"qualified-notation-token", `<!DOCTYPE r [<!ATTLIST r format NOTATION (image:png) #IMPLIED>]><r/>`},
		{"missing-public-system-separator", `<!DOCTYPE r PUBLIC "example""fixture.dtd"><r/>`},
		{"literal-less-than-in-attribute", `<!DOCTYPE r><r value="a<b"/>`},
		{"duplicate-attribute", `<!DOCTYPE r><r value="a" value="b"/>`},
		{"cdata-before-root", `<!DOCTYPE r><![CDATA[leading]]><r/>`},
		{"cdata-after-root", `<!DOCTYPE r><r/><![CDATA[trailing]]>`},
		{"unterminated-cdata", `<!DOCTYPE r><r><![CDATA[text</r>`},
		{"unsupported-version-number", `<?xml version="1.x"?><!DOCTYPE r><r/>`},
		{"malformed-xml-declaration", `<?xml version="1.0" standalone?><!DOCTYPE r><r/>`},
		{"invalid-standalone-value", `<?xml version="1.0" standalone="true"?><!DOCTYPE r><r/>`},
		{"conditional-section-in-internal-subset", `<!DOCTYPE r [<![INCLUDE[<!ELEMENT r EMPTY>]]>]><r/>`},
		{"invalid-content-model", `<!DOCTYPE r [<!ELEMENT r child>]><r/>`},
		{"invalid-mixed-content-name", `<!DOCTYPE r [<!ELEMENT r (#PCDATA|p:part:label)*>]><r/>`},
		{"entity-reference-without-semicolon", `<!DOCTYPE r><r>&amp</r>`},
		{"undeclared-entity", `<!DOCTYPE r><r>&label;</r>`},
		{"character-reference-without-semicolon", `<!DOCTYPE r><r>&#34</r>`},
		{"invalid-entity-name", `<!DOCTYPE r><r>&0label;</r>`},
		{"character-data-terminator", `<!DOCTYPE r><r>text]]></r>`},
		{"text-before-root", `<!DOCTYPE r>label<r/>`},
		{"reference-before-root", `<!DOCTYPE r>&#32;<r/>`},
		{"misplaced-declaration", `<!DOCTYPE r><r><?xml version="1.0"?></r>`},
		{"missing-attribute-separator", `<!DOCTYPE r><r a="1"b="2"/>`},
		{"missing-attribute-equals", `<!DOCTYPE r><r a "1"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := options.ParseText(t.Context(), tc.input)
			if doc != nil || !errors.Is(err, tree.ErrMalformed) {
				t.Fatalf("ParseText(%q) = %v, %v, want nil document and ErrMalformed", tc.input, doc, err)
			}
		})
	}
}

func TestParseDTDTextRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()

	const input = `<?xml version="2.0"?><!DOCTYPE catalog><catalog/>`
	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
	if doc, err := options.ParseText(t.Context(), input); doc != nil || !errors.Is(err, tree.ErrUnsupported) {
		t.Errorf("ParseText = %v, %v, want nil document and ErrUnsupported", doc, err)
	}
}

func TestParseDTDTextBoundsExpandedCDATA(t *testing.T) {
	t.Parallel()

	want := strings.Repeat("<", 20)
	input := `<!DOCTYPE r><r><![CDATA[` + want + `]]></r>`
	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
	doc, err := options.ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Root().Text(); got != want {
		t.Errorf("root text = %q, want %q", got, want)
	}

	options.Limits.MaxBytes = len(input)
	if doc, err := options.ParseText(t.Context(), input); doc != nil || !errors.Is(err, tree.ErrLimit) {
		t.Errorf("ParseText with MaxBytes = %d returned %v, %v, want nil document and ErrLimit", len(input), doc, err)
	}
}

func TestParseDTDTextPredefinedEntityDeclarations(t *testing.T) {
	t.Parallel()

	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
	for _, tc := range []struct {
		name, declarations, want string
		wantErr                  error
	}{
		{
			name:         "equivalent-predefined-values",
			declarations: `<!ENTITY lt "&#38;#60;"><!ENTITY amp "&#38;#38;"><!ENTITY gt ">"><!ENTITY quot '"'><!ENTITY apos "'">`,
			want:         `<&>"'`,
		},
		{
			name:         "different-predefined-value",
			declarations: `<!ENTITY gt "x">`,
			wantErr:      tree.ErrMalformed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			input := `<!DOCTYPE r [` + tc.declarations + `]><r>&lt;&amp;&gt;&quot;&apos;</r>`
			doc, err := options.ParseText(t.Context(), input)
			if tc.wantErr != nil {
				if doc != nil || !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseText = %v, %v, want nil document and %v", doc, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := doc.Root().Text(); got != tc.want {
				t.Errorf("root text = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseDTDTextLimitAndCancellation(t *testing.T) {
	t.Parallel()

	const input = `<!DOCTYPE r [<!ATTLIST r name CDATA "a" label CDATA "b">]><r/>`
	limits := tree.DefaultLimits()
	limits.MaxAttributesPerElement = 1
	options := tree.ParseOptions{Limits: limits, AllowDTD: true}
	if doc, err := options.ParseText(t.Context(), input); doc != nil || !errors.Is(err, tree.ErrLimit) {
		t.Errorf("attribute limit = %v, %v, want nil document and ErrLimit", doc, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	options.Limits = tree.DefaultLimits()
	if doc, err := options.ParseText(ctx, input); doc != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled parse = %v, %v, want nil document and context.Canceled", doc, err)
	}
	options.Limits.MaxBytes = len(input) - 1
	if doc, err := options.ParseText(t.Context(), input); doc != nil || !errors.Is(err, tree.ErrLimit) {
		t.Errorf("input limit = %v, %v, want nil document and ErrLimit", doc, err)
	}
}

func TestParseDTDTextExplicitAttributeOverridesDefault(t *testing.T) {
	t.Parallel()

	const input = `<!DOCTYPE r [<!ATTLIST r a CDATA 'first' b CDATA 'default'>
		<!ATTLIST r a CDATA 'second'>]><r b="explicit"/>`
	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
	doc, err := options.ParseText(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if attrs := tree.Root(doc).Attrs; len(attrs) != 2 {
		t.Fatalf("root attributes = %+v, want one a and one b", attrs)
	}
	for name, want := range map[string]string{"a": "first", "b": "explicit"} {
		if got, ok := doc.Root().Attribute(tree.Name{Local: name}); !ok || got != want {
			t.Errorf("attribute %s = %q, %v, want %q", name, got, ok, want)
		}
	}
}

func TestLanguageDTDProcessing(t *testing.T) {
	options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true, AllowRelativeNamespaces: true}
	for _, test := range []struct {
		input string
		want  string
	}{
		{`<!DOCTYPE a [<!ELEMENT a (#PCDATA)>]><a>foo</a>`, `<a>foo</a>`},
		{`<!DOCTYPE a [<!ELEMENT a (#PCDATA|entry|p:label)*>]><a xmlns:p="urn:labels">word<entry/><p:label/></a>`, `<a xmlns:p="urn:labels">word<entry></entry><p:label></p:label></a>`},
		{`<?xml version="1.0" encoding="iso-8859-1"?><!DOCTYPE a [<!ELEMENT a (#PCDATA)>]><a>é</a>`, `<a>é</a>`},
		{`<!DOCTYPE a [<!ENTITY e "hello">]><a>&e;</a>`, `<a>hello</a>`},
		{`<!DOCTYPE a [<!ENTITY e "<b>ok</b>">]><a>&e;</a>`, `<a><b>ok</b></a>`},
		{`<!DOCTYPE a [<!ATTLIST a x CDATA "x&amp;y" y NMTOKENS " a  b ">]><a/>`, `<a x="x&amp;y" y="a b"></a>`},
		{`<!DOCTYPE a [<!ATTLIST a x NMTOKENS #IMPLIED>]><a x=" a&#9; b "/>`, `<a x="a&#x9; b"></a>`},
		{`<!DOCTYPE a [<!ENTITY % d '<!ENTITY e "ok">'>%d;]><a>&e;</a>`, `<a>ok</a>`},
		{`<!DOCTYPE a [<!ELEMENT a (b,(c|d)?,e*)><!ELEMENT b EMPTY><!ELEMENT c ANY>]><a/>`, `<a></a>`},
		{`<!DOCTYPE a [<!NOTATION n PUBLIC "a"><!ENTITY e SYSTEM "urn:e" NDATA n>]><a/>`, `<a></a>`},
		{`<!DOCTYPE a [<!--x--><?p a?>]><a/>`, `<a></a>`},
	} {
		t.Run(test.input, func(t *testing.T) {
			doc, err := options.ParseText(t.Context(), test.input)
			if err != nil {
				t.Fatal(err)
			}
			var output strings.Builder
			if _, err := doc.WriteXML(t.Context(), &output, options.Limits.MaxBytes); err != nil || output.String() != test.want {
				t.Fatal(output.String(), err, "want", test.want)
			}
		})
	}
	for _, input := range []string{
		`<!DOCTYPE a [<!BOGUS a>]><a/>`,
		`<!DOCTYPE a [<!ELEMENT a (a|)>]><a/>`,
		`<!DOCTYPE a [<!ELEMENT a (a,b|c)>]><a/>`,
		`<!DOCTYPE a [<!ELEMENT a (#PCDATA|b)>]><a/>`,
		`<!DOCTYPE a [<!ATTLIST a x BAD #IMPLIED>]><a/>`,
		`<!DOCTYPE a [<!ENTITY % d "a"><!ELEMENT a (%d;)>]><a/>`,
		`<!DOCTYPE a [<!ENTITY e "&f;"><!ENTITY f "&e;">]><a>&e;</a>`,
		`<!DOCTYPE a [<!ENTITY e "<b>">]><a>&e;</b></a>`,
		`<!DOCTYPE a [<!ENTITY e "</a>">]><a>&e;`,
		`<!DOCTYPE a [<!ENTITY e SYSTEM "urn:e">]><a x="&e;"/>`,
		`<!DOCTYPE a [<!ENTITY e SYSTEM "urn:e" NDATA n>]><a>&e;</a>`,
		`<!DOCTYPE a [<!ENTITY e "%bad;">]><a/>`,
		`<!DOCTYPE a [<!--a--b-->]><a/>`,
		`<!DOCTYPE a [<?xml bad?>]><a/>`,
		`<!DOCTYPE a><!DOCTYPE a><a/>`,
		`<a/><!DOCTYPE a>`,
		`<!DOCTYPE a [<!ATTLIST a x CDATA "&missing;">]><a/>`,
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := options.ParseText(t.Context(), input); err == nil {
				t.Fatal("accepted malformed DTD/XML")
			}
		})
	}
}

func TestParseReaderPreservesSourceFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("entity source failed")
	for _, input := range []struct{ name, xml string }{
		{"complete root", `<r/>`},
		{"trailing whitespace", `<r/> `},
		{"unfinished comment", `<r><!--unfinished`},
		{"DTD entity", `<!DOCTYPE r [<!ENTITY e "value">]><r>&e;</r>`},
	} {
		for _, delivery := range []struct {
			name     string
			withData bool
		}{{"after final bytes", false}, {"with final bytes", true}} {
			for _, sourceError := range []struct {
				name string
				err  error
			}{{"source failure", failure}, {"EOF joined with source failure", errors.Join(io.EOF, failure)}} {
				t.Run(input.name+"/"+delivery.name+"/"+sourceError.name, func(t *testing.T) {
					t.Parallel()
					reader := io.MultiReader(strings.NewReader(input.xml), iotest.ErrReader(sourceError.err))
					if delivery.withData {
						reader = iotest.DataErrReader(reader)
					}
					doc, err := (tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}).ParseReader(t.Context(), reader)
					if doc != nil || !errors.Is(err, failure) {
						t.Fatalf("document=%v error=%v; want source failure", doc != nil, err)
					}
				})
			}
		}
	}
}

func TestDTDProbeRejectsInvalidReaderCounts(t *testing.T) {
	failure := errors.New("source failed")
	for _, count := range []int{-1, 4097} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
			doc, err := options.ParseReader(t.Context(), invalidCountReader{count: count, err: failure})
			if doc != nil || !errors.Is(err, io.ErrShortBuffer) || !errors.Is(err, failure) {
				t.Fatalf("document=%v error=%v; want invalid reader count and source failure", doc != nil, err)
			}
		})
	}
}

func TestDTDProbeRejectsNilReaders(t *testing.T) {
	for _, source := range []io.Reader{nil, (*strings.Reader)(nil)} {
		options := tree.ParseOptions{Limits: tree.DefaultLimits(), AllowDTD: true}
		if doc, err := options.ParseReader(t.Context(), source); doc != nil || !errors.Is(err, tree.ErrMalformed) {
			t.Fatalf("document=%v error=%v; want malformed input", doc != nil, err)
		}
	}
}

type invalidCountReader struct {
	count int
	err   error
}

func (r invalidCountReader) Read([]byte) (int, error) { return r.count, r.err }
