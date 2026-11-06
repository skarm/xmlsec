//go:build interop

package interop_test

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/saml/metadata"
	"github.com/skarm/xmlsec/saml/protocol"
)

func TestOpenSAMLAuthorityContracts(t *testing.T) {
	selected(t, "opensaml")
	f := newInteropFixture(t)
	_ = openSAMLOracle(t, f)
	cp := f.work + string(os.PathListSeparator) + os.Getenv("OPENSAML_CLASSPATH")
	command(t, f, true, nil, "javac", "-cp", cp, "-d", f.work, filepath.Join(f.root, "tests/interop/testdata/OpenSAMLAuthorityOracle.java"))
	oracle := func(t *testing.T, args ...string) {
		t.Helper()
		command(t, f, true, nil, "java", append([]string{"-Dlogback.configurationFile=" + filepath.Join(f.work, "oracle-logback.xml"), "-cp", cp, "OpenSAMLAuthorityOracle"}, args...)...)
	}
	key := generateKey(t, f.work, nameRSASHA256)
	signer := protocol.SigningKey{Key: key.signer}
	keys := []crypto.PublicKey{key.signer.Public()}
	at := time.Now().UTC()
	const requester, authority, endpoint = "https://requester.test/entity", "https://authority.test/entity", "https://authority.test/soap"
	for _, kind := range []string{"AuthnQuery", "AttributeQuery", "AuthzDecisionQuery", "AssertionIDRequest", "NameIDMappingRequest"} {
		t.Run(kind, func(t *testing.T) {
			queryPath := filepath.Join(f.work, "independent-query.xml")
			oracle(t, "query", kind, key.private, key.certificate, queryPath, requester, endpoint, at.Format(time.RFC3339Nano))
			d, err := document.Parse(t.Context(), read(t, queryPath), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			o := protocol.ExchangeOptions{Issuer: requester, Destination: endpoint, At: at, Binding: metadata.SOAP}
			var q protocol.Query
			var mapping protocol.NameIDMappingRequest
			if kind == "NameIDMappingRequest" {
				v, err := protocol.VerifyNameIDMappingRequest(t.Context(), d, keys, o)
				if err != nil {
					t.Fatal(err)
				}
				mapping = v.Request()
				d, err = protocol.SignNameIDMappingRequest(t.Context(), mapping, signer)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				v, err := protocol.VerifyQuery(t.Context(), d, keys, o)
				if err != nil {
					t.Fatal(err)
				}
				q = v.Query()
				d, err = protocol.SignQuery(t.Context(), q, signer)
				if err != nil {
					t.Fatal(err)
				}
			}
			ours := write(t, filepath.Join(f.work, "go-query.xml"), xmlBytes(t, d))
			oracle(t, "verify", ours, key.public)
			responsePath := filepath.Join(f.work, "independent-response.xml")
			oracle(t, "response", ours, key.private, key.certificate, responsePath, authority, at.Format(time.RFC3339Nano))
			raw := read(t, responsePath)
			response, err := document.Parse(t.Context(), raw, document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			requestID, _ := d.Root().Attribute(document.Name{Local: "ID"})
			options := protocol.ExchangeOptions{Issuer: authority, ExpectedRequestID: requestID, At: at, Binding: metadata.SOAP}
			if kind == "NameIDMappingRequest" {
				v, err := protocol.VerifyNameIDMappingResponse(t.Context(), response, keys, options)
				if err != nil {
					t.Fatal(err)
				}
				if err = protocol.CheckMappedPolicy(t.Context(), v.Identifier(), mapping.Policy); err != nil {
					t.Fatal(err)
				}
				response, err = protocol.SignNameIDMappingResponse(t.Context(), protocol.NameIDMappingResponse{MessageHeader: protocol.MessageHeader{Issuer: authority, IssueInstant: at}, InResponseTo: mapping.ID, Identifier: v.Identifier()}, signer)
				if err != nil {
					t.Fatal(err)
				}
				input, _ := protocol.NameIDDocument(t.Context(), mapping.NameID)
				failure, err := protocol.SignNameIDMappingResponse(t.Context(), protocol.NameIDMappingResponse{MessageHeader: protocol.MessageHeader{Issuer: authority, IssueInstant: at}, InResponseTo: mapping.ID, Status: protocol.Status{Code: protocol.Requester, Subcodes: []string{protocol.UnknownPrincipal}}, Identifier: input}, signer)
				if err != nil {
					t.Fatal(err)
				}
				oracle(t, "verify", write(t, filepath.Join(f.work, "go-error.xml"), xmlBytes(t, failure)), key.public)
			} else {
				v, err := protocol.VerifyQueryResponse(t.Context(), response, keys, q, protocol.QueryResponseOptions{ExchangeOptions: options, Audience: requester})
				if err != nil {
					t.Fatal(err)
				}
				want := 2
				if kind == "AssertionIDRequest" {
					want = 1
				}
				if len(v.Assertions()) != want {
					t.Fatal("independent assertion count")
				}
				empty, err := protocol.SignQueryResponse(t.Context(), protocol.QueryResponse{MessageHeader: protocol.MessageHeader{Issuer: authority, IssueInstant: at}, InResponseTo: q.ID}, signer)
				if err != nil {
					t.Fatal(err)
				}
				oracle(t, "verify", write(t, filepath.Join(f.work, "go-empty.xml"), xmlBytes(t, empty)), key.public)
				verified := v.Assertions()
				assertions := make([]*document.Document, 0, len(verified))
				for _, a := range verified {
					assertions = append(assertions, a.Document())
				}
				response, err = protocol.SignQueryResponse(t.Context(), protocol.QueryResponse{MessageHeader: protocol.MessageHeader{Issuer: authority, IssueInstant: at}, InResponseTo: q.ID, Assertions: assertions}, signer)
				if err != nil {
					t.Fatal(err)
				}
			}
			path := write(t, filepath.Join(f.work, "go-response.xml"), xmlBytes(t, response))
			oracle(t, "verify", path, key.public)
		})
	}
	t.Run("authority-metadata", func(t *testing.T) {
		role := func(service string) *metadata.RoleDescriptor {
			return &metadata.RoleDescriptor{Keys: []metadata.KeyDescriptor{{CertificateDER: key.cert.Raw}}, Endpoints: map[string][]metadata.Endpoint{service: {{Binding: metadata.SOAP, Location: endpoint}}, metadata.AssertionIDRequestService: {{Binding: metadata.SOAP, Location: endpoint}, {Binding: metadata.URI, Location: "https://authority.test/assertions"}}}}
		}
		d, err := metadata.Build(t.Context(), metadata.EntityDescriptor{EntityID: authority, ValidUntil: at.Add(time.Hour), AuthnAuthority: role(metadata.AuthnQueryService), AttributeAuthority: role(metadata.AttributeService), PDP: role(metadata.AuthzService)}, at, metadata.Options{})
		if err != nil {
			t.Fatal(err)
		}
		oracle(t, "schema", write(t, filepath.Join(f.work, "authority-metadata.xml"), xmlBytes(t, d)))
	})
}
