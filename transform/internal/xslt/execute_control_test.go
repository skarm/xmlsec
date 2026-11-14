package xslt //nolint:testpackage // Exercises group membership and focus in the internal executor.

import "testing"

func TestGroupingKeepsKeysAndFocus(t *testing.T) {
	t.Parallel()
	source := parseTestDocument(t, `<r><n k="A">1</n><n k="A">2</n><n k="B">3</n><n k="A">4</n></r>`)
	for _, tc := range []struct {
		name, group, key, sort, want string
	}{
		{"adjacent_repeated_keys_stay_separate", `group-adjacent="@k"`, `current-grouping-key()`, "", "A:1/3:1,2;B:2/3:3;A:3/3:4;"},
		{"starting_pattern_separates_runs", `group-starting-with="n[@k='B']"`, `string(@k)`, "", "A:1/2:1,2;B:2/2:3,4;"},
		{"ending_pattern_includes_matching_item", `group-ending-with="n[@k='B']"`, `string(@k)`, "", "A:1/2:1,2,3;A:2/2:4;"},
		{"sort_reorders_groups_and_focus", `group-by="@k"`, `current-grouping-key()`, `<xsl:sort select="current-grouping-key()" order="descending"/>`, "B:1/2:3;A:2/2:1,2,4;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `<xsl:for-each-group select="r/n" ` + tc.group + `>` + tc.sort +
				`<xsl:value-of select="` + tc.key + ` || ':' || position() || '/' || last() || ':' || string-join(current-group() ! string(.), ',') || ';'"/></xsl:for-each-group>`
			got, err := compileTestStylesheet(t, "", body).Transform(source).Serialize(t.Context())
			requireSerialization(t, got, err, tc.want, "")
		})
	}
}
