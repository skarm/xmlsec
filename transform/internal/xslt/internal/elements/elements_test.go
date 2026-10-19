package elements_test

import (
	"testing"

	"github.com/skarm/xmlsec/transform/internal/xslt/internal/elements"
)

func TestElementContexts(t *testing.T) {
	for _, tc := range []struct {
		name, version         string
		topLevel, instruction bool
	}{
		{"template", "1.0", true, false},
		{"value-of", "1.0", false, true},
		{"iterate", "3.0", false, true},
		{"not-an-xslt-element", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if elements.MinVersion(tc.name) != tc.version || elements.IsTopLevel(tc.name) != tc.topLevel || elements.IsInstruction(tc.name) != tc.instruction {
				t.Fatal("incorrect version or permitted context")
			}
		})
	}

	if !elements.IsValidChild("when", "choose") || elements.IsValidChild("when", "template") || elements.IsValidChild("value-of", "choose") {
		t.Fatal("child-only restrictions lost")
	}
}

func TestLookupReturnsOwnedMetadata(t *testing.T) {
	attrs, ok := elements.AllowedAttrs("value-of")
	if !ok {
		t.Fatal("value-of missing")
	}

	if _, ok := attrs["select"]; !ok {
		t.Fatal("select attribute missing")
	}

	delete(attrs, "select")

	again, ok := elements.AllowedAttrs("value-of")
	if !ok {
		t.Fatal("value-of missing after mutation")
	}

	if _, ok := again["select"]; !ok {
		t.Fatal("attribute metadata shared between calls")
	}

	parents := elements.ValidParents("when")
	if len(parents) == 0 {
		t.Fatal("when parents missing")
	}

	parents[0] = "invalid"

	if !elements.IsValidChild("when", "choose") {
		t.Fatal("parent metadata shared between calls")
	}
}
