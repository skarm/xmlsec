package xslt //nolint:testpackage // Exercises miscellaneous instructions through the internal compiler and invocation.

import (
	"errors"
	"testing"
)

func TestAssertionsFollowInvocationPolicy(t *testing.T) {
	t.Parallel()
	const body = `<xsl:assert test="/*/@approved = 'yes'" error-code="f:required" select="'approval required'"/><xsl:text>accepted</xsl:text>`
	for _, tc := range []struct {
		name, source, want, code string
		enabled                  bool
	}{
		{name: "disabled_assertion_does_not_terminate", source: `<r/>`, want: "accepted"},
		{name: "successful_assertion_does_not_terminate", source: `<r approved="yes"/>`, want: "accepted", enabled: true},
		{name: "failed_assertion_reports_custom_code", source: `<r/>`, code: "required", enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var message recordingMessageHandler
			invocation := compileTestStylesheet(t, "", body).Transform(parseTestDocument(t, tc.source)).MessageHandler(&message)
			got, err := invocation.Serialize(WithAssertions(t.Context(), tc.enabled))
			requireSerialization(t, got, err, tc.want, tc.code)
			if tc.code == "" {
				if message.calls != 0 {
					t.Errorf("assertion delivered %d messages, want none", message.calls)
				}
			} else {
				var detail *XSLTError
				if !errors.As(err, &detail) || detail.CodeQName().URI != "urn:unit" {
					t.Errorf("assertion error = %v, want an expanded code in urn:unit", err)
				}
				if message.calls != 1 || !message.terminate || message.message != "approval required" {
					t.Errorf("assertion message = %q; calls = %d, terminate = %t; want one terminating approval message", message.message, message.calls, message.terminate)
				}
			}
		})
	}
}
