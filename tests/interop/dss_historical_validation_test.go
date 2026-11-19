//go:build interop

package interop_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/internal/tree"
)

func TestDSSHistoricalValidation(t *testing.T) {
	selected(t, "portable")

	manifestPath := os.Getenv("XMLSEC_DSS_FIXTURES")
	endpoint := os.Getenv("XMLSEC_DSS_URL")
	runtimeJar := os.Getenv("XMLSEC_DSS_RUNTIME_JAR")
	if manifestPath == "" || endpoint == "" || runtimeJar == "" {
		if os.Getenv("XMLSEC_REQUIRE_P7_PROOFS") == "1" {
			t.Fatal("XMLSEC_DSS_FIXTURES, XMLSEC_DSS_URL and XMLSEC_DSS_RUNTIME_JAR are required")
		}

		t.Skip("optional local DSS historical compatibility fixtures/runtime")
	}

	base, err := dssLoopbackURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	var manifest dssHistoricalManifest
	decoder := json.NewDecoder(bytes.NewReader(dssReadFile(t, filepath.Dir(manifestPath), filepath.Base(manifestPath), 256<<10)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("trailing DSS manifest data:", err)
	}

	if manifest.Version != "6.5.1" || manifest.ValidationTime.IsZero() || len(manifest.Pairs) == 0 || len(manifest.Pairs) > 16 {
		t.Fatal("invalid DSS fixture version, explicit validation time or bounded pair count")
	}
	anchor, err := hex.DecodeString(manifest.TrustAnchorSHA256)
	if err != nil || len(anchor) != sha256.Size {
		t.Fatal("missing exact DSS trust-anchor certificate SHA-256")
	}
	anchorID := "C-" + strings.ToUpper(manifest.TrustAnchorSHA256)

	client := &http.Client{Timeout: time.Minute, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	dssCheckRuntime(t, client, base, runtimeJar, manifest.Version)

	directory := filepath.Dir(manifestPath)
	var policy *dssRemoteDocument
	if manifest.Policy != "" {
		policy = &dssRemoteDocument{Bytes: dssReadFile(t, directory, manifest.Policy, 1<<20), Name: filepath.Base(manifest.Policy)}
	}

	seen := map[string]struct{}{}
	for _, pair := range manifest.Pairs {
		if _, exists := seen[pair.Name]; pair.Name == "" || exists {
			t.Fatal("empty or duplicate historical pair name")
		}

		seen[pair.Name] = struct{}{}
		t.Run(pair.Name, func(t *testing.T) {
			sufficient := dssReadFile(t, directory, pair.Sufficient, 16<<20)
			insufficient := dssReadFile(t, directory, pair.Insufficient, 16<<20)
			dssCheckSameSignature(t, sufficient, insufficient)
			if pair.WantSufficient.Indication != "TOTAL_PASSED" || pair.WantSufficient.SubIndication != "" || pair.WantInsufficient.Indication != "INDETERMINATE" || pair.WantInsufficient.SubIndication == "" {
				t.Fatal("pair must specify total success and one exact indeterminate reason")
			}

			for _, item := range []struct {
				name string
				raw  []byte
				want dssExpectation
			}{{"sufficient", sufficient, pair.WantSufficient}, {"insufficient", insufficient, pair.WantInsufficient}} {
				t.Run(item.name, func(t *testing.T) {
					raw := dssPostValidation(t, client, base, dssValidationRequest{SignedDocument: dssRemoteDocument{Bytes: item.raw, Name: pair.Name + ".xml"}, Policy: policy, ValidationTime: manifest.ValidationTime})
					dssSaveReport(t, item.raw, raw)
					var report dssReports
					if err := json.Unmarshal(raw, &report); err != nil {
						t.Fatal(err)
					}

					if err := report.check(manifest.ValidationTime, item.want, anchorID); err != nil {
						t.Fatalf("DSS verdict: %v; summary=%+v\n%.4096s", err, report.SimpleReport, raw)
					}
					if err := report.checkArchiveRecovery(item.want.Indication == "TOTAL_PASSED"); err != nil {
						t.Fatal("DSS archive workflow:", err)
					}

					t.Logf("DSS %s %s/%s input-sha256=%x best-signature-time=%s", manifest.Version, item.want.Indication, item.want.SubIndication, sha256.Sum256(item.raw), item.want.BestSignatureTime.Format(time.RFC3339Nano))
				})
			}
		})
	}
}

func TestDSSHistoricalReportContracts(t *testing.T) {
	at := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	proof := at.AddDate(-1, 0, 0)
	const raw = `{"DiagnosticData":{"ValidationDate":"2026-10-25T00:00:00Z","Signature":[{"Id":"s","StructuralValidation":{"valid":true},"BasicSignature":{"SignatureIntact":true,"SignatureValid":true},"DigestMatcher":[{"DataFound":true,"DataIntact":true},{"DataFound":true,"DataIntact":true}]}]},"SimpleReport":{"ValidationTime":"2026-10-25T00:00:00Z","SignaturesCount":1,"ValidSignaturesCount":1,"signatureOrTimestampOrEvidenceRecord":[{"Signature":{"Id":"s","Indication":"TOTAL_PASSED","SubIndication":null,"BestSignatureTime":"2025-10-25T00:00:00Z","CertificateChain":{"Certificate":[{"Id":"C-ROOT","trusted":true}]}}}]},"DetailedReport":{"ValidationTime":"2026-10-25T00:00:00Z","signatureOrTimestampOrEvidenceRecord":[{"Signature":{"Id":"s"}}]}}`
	want := dssExpectation{Indication: "TOTAL_PASSED", BestSignatureTime: proof}
	for _, test := range []struct {
		name string
		from string
		to   string
	}{
		{"complete report", "", ""},
		{"missing diagnostic", `"DiagnosticData"`, `"OtherData"`},
		{"wrong signature identity", `"Id":"s","Indication"`, `"Id":"other","Indication"`},
		{"unrelated indeterminate reason", `"TOTAL_PASSED"`, `"INDETERMINATE"`},
		{"missing proof time", `"2025-10-25T00:00:00Z"`, `null`},
		{"wrong proof time", `"2025-10-25T00:00:00Z"`, `"2025-10-24T00:00:00Z"`},
		{"wrong trusted anchor", `"Id":"C-ROOT"`, `"Id":"C-OTHER"`},
		{"untrusted anchor", `"trusted":true`, `"trusted":false`},
		{"signature invalid", `"SignatureValid":true`, `"SignatureValid":false`},
		{"missing signature validity", `"SignatureValid":true`, `"SignatureValid":null`},
		{"damaged reference", `"DataIntact":true`, `"DataIntact":false`},
		{"wrong explicit validation time", `"ValidationDate":"2026-10-25T00:00:00Z"`, `"ValidationDate":"2026-10-24T00:00:00Z"`},
		{"detailed report signature mismatch", `"Signature":{"Id":"s"}`, `"Signature":{"Id":"other"}`},
		{"detailed report time mismatch", `"DetailedReport":{"ValidationTime":"2026-10-25T00:00:00Z"`, `"DetailedReport":{"ValidationTime":"2026-10-24T00:00:00Z"`},
		{"no detailed report", `"DetailedReport":{"ValidationTime":"2026-10-25T00:00:00Z","signatureOrTimestampOrEvidenceRecord":[{"Signature":{"Id":"s"}}]}`, `"DetailedReport":null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := raw
			if test.from != "" {
				value = strings.Replace(value, test.from, test.to, 1)
				if value == raw {
					t.Fatal("test mutation missed")
				}
			}

			var report dssReports
			if err := json.Unmarshal([]byte(value), &report); err != nil {
				t.Fatal(err)
			}

			err := report.check(at, want, "C-ROOT")
			if (err == nil) != (test.from == "") {
				t.Fatal(err)
			}
		})
	}

	for _, endpoint := range []string{"https://127.0.0.1:8080/", "http://example.test/", "http://localhost/", "http://127.0.0.1/?query=1", "http://user@127.0.0.1/"} {
		if _, err := dssLoopbackURL(endpoint); err == nil {
			t.Fatal("nonlocal or ambiguous endpoint accepted:", endpoint)
		}
	}

	if _, err := dssLoopbackURL("http://127.0.0.1:8080/"); err != nil {
		t.Fatal(err)
	}

	t.Run("exact indeterminate cause with intact signature", func(t *testing.T) {
		value := strings.NewReplacer(`"TOTAL_PASSED"`, `"INDETERMINATE"`, `"ValidSignaturesCount":1`, `"ValidSignaturesCount":0`, `"SubIndication":null`, `"SubIndication":"OUT_OF_BOUNDS_NO_POE"`, `"2025-10-25T00:00:00Z"`, `"2026-10-25T00:00:00Z"`).Replace(raw)
		var report dssReports
		if err := json.Unmarshal([]byte(value), &report); err != nil {
			t.Fatal(err)
		}

		want := dssExpectation{Indication: "INDETERMINATE", SubIndication: "OUT_OF_BOUNDS_NO_POE", BestSignatureTime: at}
		if err := report.check(at, want, "C-ROOT"); err != nil {
			t.Fatal(err)
		}

		want.SubIndication = "NO_CERTIFICATE_CHAIN_FOUND"
		if err := report.check(at, want, "C-ROOT"); err == nil {
			t.Fatal("unrelated missing trust cause accepted as missing historical proof")
		}
	})

	for _, metadata := range []string{"artifactId=dss-validation\nversion=6.5.1", "# generated\nversion=6.5.1\nartifactId=dss-validation\n", "artifactId=dss-validation\r\nversion=6.5.1\r\n"} {
		if !dssPinnedMetadata([]byte(metadata), "6.5.1") {
			t.Fatal("valid Maven runtime version metadata rejected")
		}
	}
	for _, metadata := range []string{"artifactId=other\nversion=6.5.1\n", "artifactId=dss-validation\nversion=6.5.10\n", "artifactId=dss-validation\nversion=6.5\n"} {
		if dssPinnedMetadata([]byte(metadata), "6.5.1") {
			t.Fatal("different DSS implementation version accepted")
		}
	}
}

func TestDSSArchiveRecoveryReportContracts(t *testing.T) {
	const raw = `{"DetailedReport":{"signatureOrTimestampOrEvidenceRecord":[{"Signature":{"ValidationProcessBasicSignature":{"Conclusion":{"Indication":"INDETERMINATE"}},"ValidationProcessLongTermData":{"Conclusion":{"Indication":"INDETERMINATE"}},"ValidationProcessArchivalData":{"Conclusion":{"Indication":"PASSED"}},"Timestamp":[{"Id":"st","Conclusion":{"Indication":"PASSED"}},{"Id":"at","Conclusion":{"Indication":"PASSED"}}]}}]},"DiagnosticData":{"Timestamp":[{"Id":"st","Type":"SIGNATURE_TIMESTAMP","BasicSignature":{"SignatureIntact":true,"SignatureValid":true},"DigestMatcher":[{"DataFound":true,"DataIntact":true}]},{"Id":"at","Type":"ARCHIVE_TIMESTAMP","BasicSignature":{"SignatureIntact":true,"SignatureValid":true},"DigestMatcher":[{"DataFound":true,"DataIntact":true}]}]}}`
	for _, test := range []struct {
		name string
		from string
		to   string
	}{
		{"archive required and verified", "", ""},
		{"current signature passed instead", `"ValidationProcessBasicSignature":{"Conclusion":{"Indication":"INDETERMINATE"}}`, `"ValidationProcessBasicSignature":{"Conclusion":{"Indication":"PASSED"}}`},
		{"LT passed instead", `"ValidationProcessLongTermData":{"Conclusion":{"Indication":"INDETERMINATE"}}`, `"ValidationProcessLongTermData":{"Conclusion":{"Indication":"PASSED"}}`},
		{"archive process did not pass", `"ValidationProcessArchivalData":{"Conclusion":{"Indication":"PASSED"}}`, `"ValidationProcessArchivalData":{"Conclusion":{"Indication":"INDETERMINATE"}}`},
		{"missing archive timestamp", `"ARCHIVE_TIMESTAMP"`, `"OTHER_TIMESTAMP"`},
		{"timestamp signature invalid", `"SignatureValid":true`, `"SignatureValid":false`},
		{"timestamp imprint invalid", `"DataIntact":true`, `"DataIntact":false`},
		{"missing detailed report", `"DetailedReport"`, `"OtherReport"`},
		{"old timestamp ignored", `"Id":"st","Conclusion":{"Indication":"PASSED"}`, `"Id":"st","Conclusion":{"Indication":"INDETERMINATE"}`},
		{"missing old timestamp trust result", `{"Id":"st","Conclusion":{"Indication":"PASSED"}},`, ``},
		{"duplicate timestamp trust identity", `"Id":"at","Conclusion"`, `"Id":"st","Conclusion"`},
		{"different timestamp trust identity", `"Id":"at","Conclusion"`, `"Id":"other","Conclusion"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := raw
			if test.from != "" {
				value = strings.Replace(value, test.from, test.to, 1)
				if value == raw {
					t.Fatal("test mutation missed")
				}
			}
			var report dssReports
			if err := json.Unmarshal([]byte(value), &report); err != nil {
				t.Fatal(err)
			}
			if err := report.checkArchiveRecovery(true); (err == nil) != (test.from == "") {
				t.Fatal(err)
			}
		})
	}
}

// DSS is a separately started, offline demonstration runtime. Only its loopback
// REST service receives these locally generated test documents. The manifest is
// generated with the native historical fixtures, not downloaded test verdicts.
type dssHistoricalManifest struct {
	Version           string              `json:"version"`
	ValidationTime    time.Time           `json:"validation_time"`
	TrustAnchorSHA256 string              `json:"trust_anchor_sha256"`
	Policy            string              `json:"policy"`
	Pairs             []dssHistoricalPair `json:"pairs"`
}

type dssHistoricalPair struct {
	Name             string         `json:"name"`
	Sufficient       string         `json:"sufficient"`
	Insufficient     string         `json:"insufficient"`
	WantSufficient   dssExpectation `json:"want_sufficient"`
	WantInsufficient dssExpectation `json:"want_insufficient"`
}

type dssExpectation struct {
	Indication        string    `json:"indication"`
	SubIndication     string    `json:"sub_indication"`
	BestSignatureTime time.Time `json:"best_signature_time"`
}

type dssRemoteDocument struct {
	Bytes []byte `json:"bytes"`
	Name  string `json:"name"`
}

type dssValidationRequest struct {
	SignedDocument dssRemoteDocument  `json:"signedDocument"`
	Policy         *dssRemoteDocument `json:"policy,omitempty"`
	ValidationTime time.Time          `json:"validationTime"`
}

type dssSignatureSummary struct {
	ID                string    `json:"Id"`
	Indication        string    `json:"Indication"`
	SubIndication     string    `json:"SubIndication"`
	BestSignatureTime time.Time `json:"BestSignatureTime"`
	CertificateChain  struct {
		Certificates []struct {
			ID      string `json:"Id"`
			Trusted *bool  `json:"trusted"`
		} `json:"Certificate"`
	} `json:"CertificateChain"`
}

type dssBasicSignature struct {
	Intact *bool `json:"SignatureIntact"`
	Valid  *bool `json:"SignatureValid"`
}

type dssDigestMatcher struct {
	Found  *bool `json:"DataFound"`
	Intact *bool `json:"DataIntact"`
}

type dssProcess struct {
	Conclusion struct {
		Indication    string `json:"Indication"`
		SubIndication string `json:"SubIndication"`
	} `json:"Conclusion"`
}

type dssDetailedSignature struct {
	ID         string     `json:"Id"`
	Basic      dssProcess `json:"ValidationProcessBasicSignature"`
	LongTerm   dssProcess `json:"ValidationProcessLongTermData"`
	Archival   dssProcess `json:"ValidationProcessArchivalData"`
	Timestamps []struct {
		ID string `json:"Id"`
		dssProcess
	} `json:"Timestamp"`
}

type dssReports struct {
	DiagnosticData struct {
		ValidationDate time.Time `json:"ValidationDate"`
		Signatures     []struct {
			ID                   string `json:"Id"`
			StructuralValidation struct {
				Valid *bool `json:"valid"`
			} `json:"StructuralValidation"`
			BasicSignature dssBasicSignature  `json:"BasicSignature"`
			DigestMatchers []dssDigestMatcher `json:"DigestMatcher"`
		} `json:"Signature"`
		Timestamps []struct {
			ID             string             `json:"Id"`
			Type           string             `json:"Type"`
			BasicSignature dssBasicSignature  `json:"BasicSignature"`
			DigestMatchers []dssDigestMatcher `json:"DigestMatcher"`
		} `json:"Timestamp"`
	} `json:"DiagnosticData"`
	SimpleReport struct {
		ValidationTime time.Time `json:"ValidationTime"`
		Count          int       `json:"SignaturesCount"`
		ValidCount     int       `json:"ValidSignaturesCount"`
		Tokens         []struct {
			Signature *dssSignatureSummary `json:"Signature"`
		} `json:"signatureOrTimestampOrEvidenceRecord"`
	} `json:"SimpleReport"`
	DetailedReport *struct {
		ValidationTime time.Time `json:"ValidationTime"`
		Tokens         []struct {
			Signature *dssDetailedSignature `json:"Signature"`
		} `json:"signatureOrTimestampOrEvidenceRecord"`
	} `json:"DetailedReport"`
}

func dssSaveReport(t *testing.T, input, report []byte) {
	t.Helper()
	directory := os.Getenv("XMLSEC_DSS_REPORT_DIR")
	if directory == "" {
		return
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	if err := os.WriteFile(filepath.Join(directory, hex.EncodeToString(digest[:])+".json"), report, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dssReadFile(t *testing.T, directory, name string, limit int64) []byte {
	t.Helper()
	if !filepath.IsLocal(name) {
		t.Fatal("DSS fixture path must stay relative:", name)
	}

	path := filepath.Join(directory, name)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		t.Fatal("DSS fixture must be a bounded regular file:", name)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	if err = errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}

	if int64(len(raw)) > limit {
		t.Fatal("DSS fixture exceeds byte limit:", name)
	}

	return raw
}

func dssLoopbackURL(endpoint string) (*url.URL, error) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(base.Hostname())
	if base.Scheme != "http" || ip == nil || !ip.IsLoopback() || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("DSS compatibility service must use an explicit HTTP loopback IP URL")
	}

	base.Path = strings.TrimRight(base.Path, "/") + "/"

	return base, nil
}

func dssCheckRuntime(t *testing.T, client *http.Client, base *url.URL, jarPath, version string) {
	t.Helper()
	jar, err := zip.OpenReader(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := jar.Close(); err != nil {
			t.Error(err)
		}
	}()

	if err := dssCheckRuntimeMetadata(jar.File, version); err != nil {
		t.Fatal(err)
	}

	raw := dssHTTP(t, client, http.MethodGet, base.String(), nil)
	pageText := html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(string(raw), " "))
	if !regexp.MustCompile(`(?s)DSS Demonstration WebApp[^0-9]{0,160}` + regexp.QuoteMeta(version) + `(?:[^0-9.]|$)`).MatchString(pageText) {
		t.Fatal("DSS endpoint does not advertise the pinned runtime version")
	}
}

func dssCheckRuntimeMetadata(files []*zip.File, version string) error {
	const (
		metadataPath  = "META-INF/maven/eu.europa.ec.joinup.sd-dss/dss-validation/pom.properties"
		metadataLimit = 4096
	)

	var metadata *zip.File
	for _, file := range files {
		if file.Name != metadataPath {
			continue
		}

		if metadata != nil {
			return errors.New("DSS runtime JAR has duplicate implementation metadata")
		}

		metadata = file
	}

	if metadata == nil {
		return errors.New("DSS runtime JAR has no canonical implementation metadata")
	}

	stream, err := metadata.Open()
	if err != nil {
		return err
	}

	raw, readErr := io.ReadAll(io.LimitReader(stream, metadataLimit+1))
	if err := errors.Join(readErr, stream.Close()); err != nil {
		return err
	}

	if len(raw) > metadataLimit || !dssPinnedMetadata(raw, version) {
		return errors.New("DSS runtime JAR has no exact pinned implementation version")
	}

	return nil
}

func dssPinnedMetadata(raw []byte, version string) bool {
	var artifact, implementation bool
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		switch key, value, _ := bytes.Cut(line, []byte{'='}); string(key) {
		case "artifactId":
			if artifact || string(value) != "dss-validation" {
				return false
			}
			artifact = true
		case "version":
			if implementation || string(value) != version {
				return false
			}
			implementation = true
		}
	}

	return artifact && implementation
}

func dssPostValidation(t *testing.T, client *http.Client, base *url.URL, value dssValidationRequest) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return dssHTTP(t, client, http.MethodPost, base.ResolveReference(&url.URL{Path: "services/rest/validation/validateSignature"}).String(), raw)
}

func dssHTTP(t *testing.T, client *http.Client, method, endpoint string, raw []byte) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if method == http.MethodGet {
		request.Header.Set("Accept", "text/html")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	body, readErr := io.ReadAll(io.LimitReader(response.Body, (32<<20)+1))
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal(err)
	}

	if len(body) > 32<<20 || response.StatusCode != http.StatusOK {
		t.Fatalf("DSS HTTP status=%d, bounded response bytes=%d: %.1024s", response.StatusCode, len(body), body)
	}

	return body
}

func dssCheckSameSignature(t *testing.T, left, right []byte) {
	t.Helper()
	if bytes.Equal(left, right) {
		t.Fatal("historical counterfactual did not change evidence")
	}

	var previousInfo, previousValue []byte
	for _, raw := range [][]byte{left, right} {
		doc := xmlDoc(t, raw)
		signature := one(t, tree.Root(doc), ds, "Signature")
		info := one(t, signature, ds, "SignedInfo")
		algorithm := attr(one(t, info, ds, "CanonicalizationMethod"), "Algorithm")
		var canonical bytes.Buffer
		if err := c14n.WriteElement(t.Context(), &canonical, tree.Wrap(doc, info), c14n.Options{Algorithm: algorithm}); err != nil {
			t.Fatal(err)
		}

		value := decode64(t, text(one(t, signature, ds, "SignatureValue")))
		if previousInfo != nil && (!bytes.Equal(previousInfo, canonical.Bytes()) || !bytes.Equal(previousValue, value)) {
			t.Fatal("historical pair changed SignedInfo or SignatureValue")
		}

		previousInfo = bytes.Clone(canonical.Bytes())
		previousValue = value
	}
}

func dssTrue(value *bool) bool { return value != nil && *value }
