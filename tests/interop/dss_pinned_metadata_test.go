//go:build interop

package interop_test

import "testing"

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
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dssPinnedMetadata([]byte(tc.raw), version); got != tc.want {
				t.Errorf("dssPinnedMetadata(%q, %q) = %t, want %t", tc.raw, version, got, tc.want)
			}
		})
	}
}
