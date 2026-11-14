package main

import (
	"encoding/xml"
	"testing"

	"github.com/skarm/xmlsec/xmldsig"
)

func TestExample(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureTemplateTargetsPayload(t *testing.T) {
	for _, id := range []string{"first", "second"} {
		t.Run(id, func(t *testing.T) {
			var template struct {
				XMLName    xml.Name
				ID         string `xml:"Id,attr"`
				References []struct {
					URI string `xml:"URI,attr"`
				} `xml:"SignedInfo>Reference"`
			}
			if err := xml.Unmarshal([]byte(signature(id)), &template); err != nil {
				t.Fatalf("decode signature template for %q: %v", id, err)
			}
			if want := (xml.Name{Space: xmldsig.Namespace, Local: "Signature"}); template.XMLName != want || template.ID != id {
				t.Errorf("template element=%v, ID=%q, want %v with ID %q", template.XMLName, template.ID, want, id)
			}
			if refs := template.References; len(refs) != 1 || refs[0].URI != "#payload" {
				t.Errorf("template references=%+v, want exactly one reference to #payload", refs)
			}
		})
	}
}
