package pattern

import (
	"errors"
	"testing"
)

// With no captures or counters, adding backreference support changes only the
// visited-state representation. Both paths must charge exactly the same cells.
func TestSimpleStateBudgetMatchesGeneralStateBudget(t *testing.T) {
	t.Parallel()
	for _, maximum := range []int{1, 4, 5, 64, 4096} {
		simple, err := newMachine(t.Context(), &Program{}, "", Work{MaxCells: maximum})
		if err != nil {
			t.Fatal(err)
		}
		general, err := newMachine(t.Context(), &Program{backrefs: true}, "", Work{MaxCells: maximum})
		if err != nil {
			t.Fatal(err)
		}
		for i := range 1024 {
			// Cross varint-width boundaries and revisit prior states.
			s := state{pc: i % 17, pos: (i % 31) << (i % 24)}
			stackCells := i % 3
			got, gotErr := simple.visit(s, stackCells)
			want, wantErr := general.visit(s, stackCells)
			if got != want || !errors.Is(gotErr, wantErr) || simple.cells != general.cells {
				t.Fatalf("budget=%d step=%d: %v/%v/%d; want %v/%v/%d", maximum, i, got, gotErr, simple.cells, want, wantErr, general.cells)
			}
		}
	}
}
