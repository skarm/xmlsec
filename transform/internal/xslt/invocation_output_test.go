package xslt //nolint:testpackage // Exercises concurrent ownership of recorded output definitions.

import (
	"sync"
	"testing"
)

func TestResolvedOutputConcurrentSnapshotOwnership(t *testing.T) {
	t.Parallel()

	var state resolvedOutputState
	var workers sync.WaitGroup

	for range 8 {
		workers.Go(func() {
			for range 64 {
				separator := "original"
				def := &OutputDef{
					ResolvedCharMap:  map[rune]string{'x': "original"},
					UseCharacterMaps: []string{"original"},
					ItemSeparator:    &separator,
				}
				state.store(def)

				def.ResolvedCharMap['x'] = "changed input"
				def.UseCharacterMaps[0] = "changed input"
				separator = "changed input"

				snapshot := state.snapshot()
				if snapshot == nil || snapshot.ResolvedCharMap['x'] != "original" || len(snapshot.UseCharacterMaps) != 1 || snapshot.UseCharacterMaps[0] != "original" || snapshot.ItemSeparator == nil || *snapshot.ItemSeparator != "original" {
					t.Error("recorded output changed through another caller's input or snapshot")
					return
				}

				snapshot.ResolvedCharMap['x'] = "changed snapshot"
				snapshot.UseCharacterMaps[0] = "changed snapshot"
				*snapshot.ItemSeparator = "changed snapshot"
			}
		})
	}

	workers.Wait()

	snapshot := state.snapshot()
	if snapshot.ResolvedCharMap['x'] != "original" || snapshot.UseCharacterMaps[0] != "original" || *snapshot.ItemSeparator != "original" {
		t.Fatal("recorded output retained mutable snapshot storage")
	}
}
