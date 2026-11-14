package xslt //nolint:testpackage // Exercises the serializer with XDM documents and output definitions.

import (
	"strings"
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestSerializeItemsUsesRequestedSeparator(t *testing.T) {
	t.Parallel()
	const delimiter = "|"
	for _, tc := range []struct {
		name, want string
		separator  *string
		absent     bool
	}{
		{name: "default_newline", want: "alpha\n<item/>\nomega"},
		{name: "custom_separator", want: "alpha|<item/>|omega", separator: new(delimiter)},
		{name: "absent_separator", want: "alpha<item/>omega", absent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := parseTestDocument(t, `<item/>`)
			items := xdm.ItemSlice{stringItem("alpha"), xdm.NodeItem{Node: doc.DocumentElement()}, stringItem("omega")}
			definition := OutputDef{Method: "xml", OmitDeclaration: true, ItemSeparator: tc.separator, ItemSeparatorAbsent: tc.absent}
			var output strings.Builder
			err := SerializeItems(t.Context(), &output, items, doc, &definition)
			requireSerialization(t, output.String(), err, tc.want, "")
		})
	}
}
