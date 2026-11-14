package xdm_test

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xdm"
)

func TestMergeMapsCombineEmptyValues(t *testing.T) {
	t.Parallel()

	for _, values := range [][]xdm.Sequence{{nil, xdm.SingleString("a")}, {xdm.SingleString("a"), nil}, {nil, nil}} {
		maps := []xdm.MapItem{xdm.SingleEntryMap(stringKey("key"), values[0]), xdm.SingleEntryMap(stringKey("key"), values[1])}
		merged, err := xdm.MergeMaps(maps, xdm.MergeCombine)
		if err != nil {
			t.Fatal(err)
		}
		value, ok := merged.Get(stringKey("key"))
		if !ok || merged.Size() != 1 {
			t.Fatal("combining an empty value lost its key")
		}
		if xdm.SequenceLen(values[0])+xdm.SequenceLen(values[1]) == 0 {
			assertStringItems(t, value)
		} else {
			assertStringItems(t, value, "a")
		}
	}
}
