package saml_test

import (
	"context"
	"testing"
	"time"

	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/sp"
)

// BenchmarkLogin includes SP initiation, IdP verification and issuance, and SP consumption.
func BenchmarkLogin(b *testing.B) {
	s := setup(b)
	b.ReportAllocs()

	for b.Loop() {
		_, req, browser := begin(b, s, metadata.HTTPRedirect)

		issued, err := s.idp.Issue(context.Background(), req, auth(), testcert.Now().Add(2*time.Second))
		if err != nil {
			b.Fatal(err)
		}

		if _, err := s.sp.ConsumePOST(context.Background(), issued.POSTBody(), sp.ConsumeOptions{At: testcert.Now().Add(3 * time.Second), BrowserBinding: browser}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSPBegin(b *testing.B) {
	s := setup(b)
	browser := make([]byte, 32)
	opts := sp.BeginOptions{IDP: idpID, Binding: metadata.HTTPRedirect, BrowserBinding: browser, At: testcert.Now()}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := s.sp.Begin(context.Background(), opts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIdPAcceptRedirect(b *testing.B) {
	s := setup(b)
	out, _, _ := begin(b, s, metadata.HTTPRedirect)
	query := out.RawQuery()

	b.ReportAllocs()

	for b.Loop() {
		if _, err := s.idp.AcceptRedirect(context.Background(), query, spID, ssoRedirect, testcert.Now()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIdPIssue(b *testing.B) {
	s := setup(b)
	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		_, request, _ := begin(b, s, metadata.HTTPRedirect)
		b.StartTimer()

		if _, err := s.idp.Issue(context.Background(), request, auth(), testcert.Now().Add(2*time.Second)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSPConsumePOST(b *testing.B) {
	s := setup(b)
	b.ReportAllocs()

	for b.Loop() {
		b.StopTimer()
		_, request, browser := begin(b, s, metadata.HTTPRedirect)

		issued, err := s.idp.Issue(context.Background(), request, auth(), testcert.Now().Add(2*time.Second))
		if err != nil {
			b.Fatal(err)
		}

		form := issued.POSTBody()

		b.StartTimer()

		if _, err := s.sp.ConsumePOST(context.Background(), form, sp.ConsumeOptions{At: testcert.Now().Add(3 * time.Second), BrowserBinding: browser}); err != nil {
			b.Fatal(err)
		}
	}
}
