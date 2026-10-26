package pki

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sort"
	"time"
)

func constructCRLViews(ctx context.Context, group []*authenticatedCRL, at time.Time, o CRLOptions) ([]completeCRLView, error) {
	if err := checkCRLSequence(group); err != nil {
		return nil, err
	}

	var views []completeCRLView

	for _, base := range group {
		if base.list.base == nil && crlFresh(base.list, at, o) {
			views = append(views, completeCRLView{base: base, this: base.list.this})
		}
	}

	if !o.DisableDeltaCRLs {
		for _, delta := range group {
			if delta.list.base == nil || !crlFresh(delta.list, at, o) {
				continue
			}

			var newest *authenticatedCRL

			for _, base := range group {
				if !compatibleCRLBase(base.list, delta.list) {
					continue
				}

				if newest == nil || base.list.number.Cmp(newest.list.number) > 0 {
					newest = base
				}
			}

			if newest != nil {
				views = append(views, completeCRLView{base: newest, delta: delta, this: delta.list.this})
			}
		}
	}

	if err := checkEquivalentCRLViews(ctx, views); err != nil {
		return nil, err
	}

	sort.Slice(views, func(i, j int) bool { return compareCRLOrder(views[i].source(), views[j].source()) > 0 })

	return views, nil
}

func compatibleCRLBase(base, delta *parsedCRL) bool {
	return base.base == nil && base.number != nil && base.number.Cmp(delta.base) >= 0 && base.number.Cmp(delta.number) < 0 && !base.this.After(delta.this) && bytes.Equal(base.authorityKeyID, delta.authorityKeyID)
}

func (view completeCRLView) crlNumber() *big.Int {
	if view.delta != nil {
		return view.delta.list.number
	}

	return view.base.list.number
}

func (view completeCRLView) source() *parsedCRL {
	if view.delta != nil {
		return view.delta.list
	}

	return view.base.list
}

func checkEquivalentCRLViews(ctx context.Context, views []completeCRLView) error {
	// RFC5280§5.2.3 permits simultaneous complete/delta CRLs with one number
	// only when their effective revocation information is identical.
	byNumber := make(map[string]completeCRLView)

	for _, view := range views {
		if err := ctx.Err(); err != nil {
			return err
		}

		number := view.crlNumber()
		if number == nil {
			continue
		}

		key := number.String()

		old, exists := byNumber[key]
		if exists && ((old.delta == nil) != (view.delta == nil)) {
			same, err := equalCRLViewState(ctx, old, view)
			if err != nil {
				return err
			}

			if !same {
				return fmt.Errorf("%w: simultaneous complete/delta CRL disagreement", ErrEvidence)
			}
		}

		byNumber[key] = view
	}

	return nil
}

type crlState struct {
	entries  map[*crlEntry]struct{}
	byIssuer map[string]*crlEntry
}

func (state crlState) find(entry *crlEntry) *crlEntry {
	for _, key := range crlEntryNames(entry) {
		if item := state.byIssuer[key]; item != nil {
			return item
		}
	}

	return nil
}

func (state crlState) apply(entry *crlEntry) {
	if old := state.find(entry); old != nil {
		delete(state.entries, old)

		for _, key := range crlEntryNames(old) {
			delete(state.byIssuer, key)
		}
	}

	if entry.reason == 8 {
		return
	}

	state.entries[entry] = struct{}{}
	for _, key := range crlEntryNames(entry) {
		state.byIssuer[key] = entry
	}
}

func crlEntryNames(entry *crlEntry) []string {
	keys := make([]string, 0, len(entry.issuers))
	for _, name := range entry.issuers {
		if name.tag == 4 {
			keys = append(keys, name.key+"/"+entry.serial.String())
		}
	}

	return keys
}

func crlViewState(ctx context.Context, view completeCRLView) (crlState, error) {
	state := crlState{entries: make(map[*crlEntry]struct{}, len(view.base.list.entries)), byIssuer: make(map[string]*crlEntry, len(view.base.list.entries))}

	apply := func(entries []crlEntry) error {
		for index := range entries {
			if index&255 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}

			state.apply(&entries[index])
		}

		return nil
	}
	if err := apply(view.base.list.entries); err != nil {
		return state, err
	}

	if view.delta != nil {
		if err := apply(view.delta.list.entries); err != nil {
			return state, err
		}
	}

	return state, nil
}

func equalCRLViewState(ctx context.Context, a, b completeCRLView) (bool, error) {
	left, err := crlViewState(ctx, a)
	if err != nil {
		return false, err
	}

	right, err := crlViewState(ctx, b)
	if err != nil {
		return false, err
	}

	if len(left.entries) != len(right.entries) {
		return false, nil
	}

	for item := range left.entries {
		other := right.find(item)
		if other == nil || item.reason != other.reason || !item.revoked.Equal(other.revoked) || !item.invalidity.Equal(other.invalidity) {
			return false, nil
		}
	}

	return true, ctx.Err()
}
