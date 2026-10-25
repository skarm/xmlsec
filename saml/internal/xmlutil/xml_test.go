package xmlutil_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/internal/profile"

	"github.com/skarm/xmlsec/saml/internal/xmlutil"
)

func TestSimpleTextSegmentsAndBudget(t *testing.T) {
	for _, text := range []string{"<r>ab</r>", "<r>a<!--ignored--><?ignored test?><![CDATA[b]]></r>", "<r>ab<!--ignored--></r>"} {
		doc, err := document.ParseReader(t.Context(), strings.NewReader(text), document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}

		if got, err := xmlutil.Simple(doc.Root(), 2); got != "ab" || err != nil {
			t.Fatal("simple content", got, err)
		}

		if got, err := xmlutil.Simple(doc.Root(), 1); got != "" || !errors.Is(err, profile.ErrSchema) {
			t.Fatal("simple content budget", got, err)
		}
	}
}

func TestSimpleTextAvoidsCopiesBeforeBudget(t *testing.T) {
	for _, fixture := range []string{
		`<r a="allowed">` + strings.Repeat("x", 1<<20) + `</r>`,
		`<r a="allowed">` + strings.Repeat("x", 1<<19) + `<!--split-->` + strings.Repeat("x", 1<<19) + `</r>`,
	} {
		doc, err := document.ParseReader(t.Context(), strings.NewReader(fixture), document.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}

		if count := testing.AllocsPerRun(3, func() {
			if got, err := xmlutil.SimpleText(doc.Root(), 1024); got != "" || !errors.Is(err, profile.ErrSchema) {
				t.Fatal("budget", len(got), err)
			}
		}); count != 0 {
			t.Fatal("over-budget text allocated", count)
		}
	}

	valid, err := document.ParseReader(t.Context(), strings.NewReader(`<r a="allowed">a<!--split-->b</r>`), document.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	if got, err := xmlutil.SimpleText(valid.Root(), 2); got != "ab" || err != nil {
		t.Fatal("attributes were not validated separately", got, err)
	}

	for _, fixture := range []struct {
		text string
		want bool
	}{{"<r> \t<!--split-->\n<?pi ok?></r>", true}, {"<r> x </r>", false}, {"<r><x/></r>", false}} {
		doc, err := document.ParseReader(t.Context(), strings.NewReader(fixture.text), document.DefaultLimits())
		if err != nil || xmlutil.EmptyContent(doc.Root()) != fixture.want {
			t.Fatal("empty content", fixture.text, err)
		}
	}
}
