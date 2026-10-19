package tree_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	treepkg "github.com/skarm/xmlsec/internal/tree"
)

func TestFragmentUsesSemanticLimits(t *testing.T) {
	limits := treepkg.DefaultLimits()
	limits.MaxBytes = 1
	limits.MaxNodes = 1
	limits.MaxDepth = 1

	d, err := treepkg.ParseFragment(context.Background(), []byte("a"), limits)
	if err != nil || len(treepkg.Children(d)) != 1 || treepkg.Children(d)[0].Data != "a" {
		t.Fatal(d, err)
	}

	if _, err := treepkg.ParseFragment(context.Background(), []byte("ab"), limits); !errors.Is(err, treepkg.ErrLimit) {
		t.Fatal("fragment bytes were not bounded", err)
	}

	limits = treepkg.DefaultLimits()
	limits.MaxDepth = 512
	limits.MaxNodes = 512

	data := []byte(strings.Repeat("<n>", 512) + strings.Repeat("</n>", 512))
	if _, err := treepkg.ParseFragment(context.Background(), data, limits); err != nil {
		t.Fatal("synthetic root consumed a depth/node slot", err)
	}

	for _, xml := range []string{`<!DOCTYPE r [<!ENTITY x "x">]><r>&x;</r>`, `<p:r/>`, `<r a="1" a="2"/>`} {
		if _, err := treepkg.ParseFragment(context.Background(), []byte(xml), treepkg.DefaultLimits()); err == nil {
			t.Error("invalid fragment accepted", xml)
		}
	}
}
