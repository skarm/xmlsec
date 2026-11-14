package saml_test

import (
	"maps"
	"runtime/metrics"
	"testing"
)

func TestSoakPausePercentiles(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after []uint64
		want          map[string]float64
	}{
		{
			name:   "no_new_pauses",
			before: []uint64{20, 10, 3},
			after:  []uint64{20, 10, 3},
			want:   map[string]float64{"p50": 0, "p95": 0, "p99": 0},
		},
		{
			name:   "counts_only_new_pauses_and_uses_upper_bucket_edge",
			before: []uint64{20, 200, 3},
			after:  []uint64{70, 245, 8},
			want:   map[string]float64{"p50": 125, "p95": 250, "p99": 500},
		},
		{
			name:   "rounds_fractional_rank_up",
			before: []uint64{0, 0, 0},
			after:  []uint64{1, 0, 2},
			want:   map[string]float64{"p50": 500, "p95": 500, "p99": 500},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buckets := []float64{0, 0.125, 0.25, 0.5}
			before := metrics.Float64Histogram{Buckets: buckets, Counts: tc.before}
			after := metrics.Float64Histogram{Buckets: buckets, Counts: tc.after}
			if got := soakPausePercentiles(before, after); !maps.Equal(got, tc.want) {
				t.Errorf("pause percentiles = %v ms, want %v ms", got, tc.want)
			}
		})
	}
}
