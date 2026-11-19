//go:build interop

package interop_test

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

func TestDSSPinnedMetadata(t *testing.T) {
	const version = "6.5.1"
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{name: "exact_properties", raw: "version=6.5.1\nartifactId=dss-validation\n", want: true},
		{name: "windows_line_endings", raw: "artifactId=dss-validation\r\nversion=6.5.1\r\n", want: true},
		{name: "wrong_artifact", raw: "artifactId=dss-model\nversion=6.5.1\n"},
		{name: "version_with_suffix", raw: "artifactId=dss-validation\nversion=6.5.1-SNAPSHOT\n"},
		{name: "version_only_in_comment", raw: "artifactId=dss-validation\n#version=6.5.1\n"},
		{name: "conflicting_versions", raw: "artifactId=dss-validation\nversion=6.5.1\nversion=6.5.2\n"},
		{name: "conflicting_artifacts", raw: "artifactId=dss-validation\nartifactId=dss-model\nversion=6.5.1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dssPinnedMetadata([]byte(tc.raw), version); got != tc.want {
				t.Errorf("dssPinnedMetadata(%q, %q) = %t, want %t", tc.raw, version, got, tc.want)
			}
		})
	}

	checkDSSRuntimeArchives(t, version)
}

func checkDSSRuntimeArchives(t *testing.T, version string) {
	t.Helper()

	const (
		canonical = "META-INF/maven/eu.europa.ec.joinup.sd-dss/dss-validation/pom.properties"
		unrelated = "META-INF/maven/example.test/dss-validation/pom.properties"
	)

	for _, tc := range []struct {
		name    string
		entries []string
		want    bool
	}{
		{"canonical", []string{canonical}, true},
		{"unrelated", []string{unrelated}, false},
		{"also unrelated", []string{canonical, unrelated}, true},
		{"duplicate canonical entries", []string{canonical, canonical}, false},
	} {
		var contents bytes.Buffer
		writer := zip.NewWriter(&contents)
		for _, entry := range tc.entries {
			properties, err := writer.Create(entry)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := io.WriteString(properties, "artifactId=dss-validation\nversion="+version+"\n"); err != nil {
				t.Fatal(err)
			}
		}

		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		archive, err := zip.NewReader(bytes.NewReader(contents.Bytes()), int64(contents.Len()))
		if err != nil {
			t.Fatal(err)
		}

		if err := dssCheckRuntimeMetadata(archive.File, version); (err == nil) != tc.want {
			t.Errorf("%s: metadata validation returned %v, want accepted = %t", tc.name, err, tc.want)
		}
	}
}
