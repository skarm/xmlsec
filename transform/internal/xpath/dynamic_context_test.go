package xpath //nolint:testpackage // Tests private evaluator context.

import (
	"context"
	"testing"
	"time"
)

func TestEvaluationContextOwnsItsConfiguration(t *testing.T) {
	at := time.Date(2026, 1, 1, 2, 3, 4, 0, time.UTC)
	original := EvaluationContext{CurrentTime: at, Language: "fr", Timezone: time.FixedZone("", 3600)}
	ctx := WithEvaluationContext(context.Background(), original)
	original.CurrentTime = at.Add(time.Hour)
	original.Language = "en"

	for range 2 {
		var ec evalContext
		applyBudget(ctx, &ec)

		if !ec.currentTime.Equal(at) || ec.defaultLanguage != "fr" || ec.implicitTimezone != original.Timezone {
			t.Fatal("configuration changed across nested evaluations")
		}
	}

	if got := CurrentTime(ctx, time.Time{}); !got.Equal(at) {
		t.Fatalf("invocation time: %v", got)
	}
}
