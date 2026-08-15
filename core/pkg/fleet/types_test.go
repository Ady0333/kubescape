package fleet

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update-golden", false, "regenerate the fleet report golden fixture under testdata/")

// TestFleetReportGoldenFile pins the serialised shape of the report.
//
// The JSON is what a CI job or a dashboard consumes, so a field renamed or
// dropped by accident breaks consumers rather than the compiler. Comparing
// against a golden fixture makes any change to the envelope show up as a diff
// at review time. A fixed GeneratedAt keeps the output deterministic; run with
// `go test -update-golden` to regenerate the fixture.
func TestFleetReportGoldenFile(t *testing.T) {
	report := FleetReport{
		Metadata: FleetMetadata{
			GeneratedAt:      time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC),
			KubescapeVersion: "v3.0.0",
			Contexts:         []string{"prod", "staging", "dr"},
		},
		Clusters: []ClusterResult{
			{
				ClusterID:       "prod",
				Context:         "prod",
				Status:          ClusterScanned,
				ComplianceScore: score(72),
				Coverage: &cautils.ScanCoverage{
					CoverageScore:     88,
					EvaluatedControls: 44,
					TotalControls:     50,
					Degraded:          true,
				},
				Duration: "4m12s",
			},
			{
				ClusterID: "dr",
				Context:   "dr",
				Status:    ClusterUnreachable,
				Error:     "context deadline exceeded",
			},
		},
		ControlMatrix: BuildControlMatrix([]ClusterResult{
			scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 18)),
			scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
		}),
	}

	got, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "fleetreport_golden.json")
	if *updateGolden {
		require.NoError(t, os.WriteFile(goldenPath, got, 0o600))
	}

	want, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden fixture missing — run `go test -update-golden`")
	assert.Equal(t, string(want), string(got), "fleet report JSON diverged from testdata/fleetreport_golden.json")
}

// TestClusterResultOmitsUnmeasuredFields checks that a cluster which was never
// scanned serialises without the fields it has no value for, rather than with
// zeroes. A fabricated "0% compliant, 0% covered" row sitting next to real
// measurements is worse than an absent one, because it reads as a finding.
func TestClusterResultOmitsUnmeasuredFields(t *testing.T) {
	raw, err := json.Marshal(unreachableCluster("dr", "no route to host"))
	require.NoError(t, err)

	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &decoded))

	for _, key := range []string{"report", "complianceScore", "coverage"} {
		assert.NotContains(t, decoded, key, "an unscanned cluster must not carry a %q key", key)
	}
	assert.Contains(t, decoded, "status", "every cluster must carry a status")
	assert.Contains(t, decoded, "error", "an unscanned cluster must carry the error that produced its status")
}

func TestFleetReportRoundTrips(t *testing.T) {
	want := FleetReport{
		Metadata: FleetMetadata{
			GeneratedAt: time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC),
			Contexts:    []string{"prod", "staging"},
		},
		Clusters: []ClusterResult{unreachableCluster("dr", "no route to host")},
		ControlMatrix: BuildControlMatrix([]ClusterResult{
			scannedCluster("prod", notEvaluated("C-0260", "Missing network policy")),
		}),
	}

	raw, err := json.Marshal(want)
	require.NoError(t, err)

	var got FleetReport
	require.NoError(t, json.Unmarshal(raw, &got))

	assert.True(t, got.Metadata.GeneratedAt.Equal(want.Metadata.GeneratedAt))
	require.Len(t, got.Clusters, 1)
	assert.Equal(t, ClusterUnreachable, got.Clusters[0].Status)

	require.Len(t, got.ControlMatrix.Controls, 1)
	assert.Equal(t, CellNotEvaluated, got.ControlMatrix.Controls[0].ByCluster["prod"].Status)
}

func TestClusterResultScanned(t *testing.T) {
	tests := []struct {
		name   string
		result ClusterResult
		want   bool
	}{
		{
			name:   "scanned with a report",
			result: scannedCluster("prod", passed("C-0016", "Allow privilege escalation")),
			want:   true,
		},
		{
			name:   "scanned status but no report is not usable data",
			result: ClusterResult{ClusterID: "prod", Status: ClusterScanned},
			want:   false,
		},
		{
			name:   "unreachable",
			result: unreachableCluster("dr", "no route to host"),
			want:   false,
		},
		{
			name:   "errored",
			result: ClusterResult{ClusterID: "dr", Status: ClusterError, Error: "policy download failed"},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.Scanned())
		})
	}
}

func TestClusterResultScored(t *testing.T) {
	scanned := scannedCluster("prod", passed("C-0016", "Allow privilege escalation"))

	noScore := scannedCluster("staging", passed("C-0016", "Allow privilege escalation"))
	noScore.ComplianceScore = nil

	noCoverage := scannedCluster("dr", passed("C-0016", "Allow privilege escalation"))
	noCoverage.Coverage = nil

	tests := []struct {
		name   string
		result ClusterResult
		want   bool
	}{
		{name: "scanned with both measurements", result: scanned, want: true},
		{name: "scanned but never scored", result: noScore, want: false},
		{name: "scanned but no coverage recorded", result: noCoverage, want: false},
		{name: "unreachable", result: unreachableCluster("dr", "no route to host"), want: false},
		{
			name:   "cancelled before it ran",
			result: ClusterResult{ClusterID: "dr", Status: ClusterCancelled},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.result.Scored())
		})
	}
}
