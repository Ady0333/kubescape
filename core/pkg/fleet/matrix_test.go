package fleet

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildControlMatrix(t *testing.T) {
	tests := []struct {
		name     string
		results  []ClusterResult
		wantRows []string
		assert   func(t *testing.T, matrix FleetControlMatrix)
	}{
		{
			name: "control present in every cluster gets a cell per cluster",
			results: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 4)),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantRows: []string{"C-0016"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				row := matrix.Controls[0]
				require.Len(t, row.ByCluster, 2)
				requireCell(t, row, "prod", CellFailed)
				requireCell(t, row, "staging", CellPassed)

				assert.Equal(t, 4, row.ByCluster["prod"].FailedResources)
				assert.Equal(t, "Allow privilege escalation", row.Name)
				assert.Equal(t, apis.SeverityHighString, row.Severity)
			},
		},
		{
			name: "control missing from one cluster leaves that cluster out of the row",
			results: []ClusterResult{
				scannedCluster("prod",
					failed("C-0016", "Allow privilege escalation", 1),
					passed("C-0038", "Host PID/IPC privileges"),
				),
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantRows: []string{"C-0016", "C-0038"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				hostPID := matrix.Controls[1]
				assert.NotContains(t, hostPID.ByCluster, "staging",
					"staging did not run C-0038, so it should have no cell in that row")
				requireCell(t, hostPID, "prod", CellPassed)
			},
		},
		{
			name: "a control that could not be evaluated is not reported as skipped",
			results: []ClusterResult{
				scannedCluster("prod", notEvaluated("C-0260", "Missing network policy")),
				scannedCluster("staging", skipped("C-0260", "Missing network policy")),
			},
			wantRows: []string{"C-0260"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				// Both clusters record the control as apis.StatusSkipped and only
				// the sub-status tells them apart. Collapsing them here would hide
				// a coverage gap behind an apparent agreement.
				requireCell(t, matrix.Controls[0], "prod", CellNotEvaluated)
				requireCell(t, matrix.Controls[0], "staging", CellSkipped)
			},
		},
		{
			name: "unreachable clusters contribute no cells",
			results: []ClusterResult{
				scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
				unreachableCluster("dr", "context deadline exceeded"),
			},
			wantRows: []string{"C-0016"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				row := matrix.Controls[0]
				assert.NotContains(t, row.ByCluster, "dr",
					"dr was never scanned, so it must not appear as a cell")
				assert.Len(t, row.ByCluster, 1)
			},
		},
		{
			name: "a scanned status with a nil report is skipped rather than dereferenced",
			results: []ClusterResult{
				{ClusterID: "prod", Context: "prod", Status: ClusterScanned},
				scannedCluster("staging", passed("C-0016", "Allow privilege escalation")),
			},
			wantRows: []string{"C-0016"},
			assert: func(t *testing.T, matrix FleetControlMatrix) {
				assert.NotContains(t, matrix.Controls[0].ByCluster, "prod",
					"a cluster with no report must not produce a cell")
			},
		},
		{
			name: "every cluster failing yields an empty matrix, not a panic",
			results: []ClusterResult{
				unreachableCluster("prod", "no route to host"),
				{ClusterID: "dr", Context: "dr", Status: ClusterError, Error: "policy download failed"},
			},
			wantRows: []string{},
		},
		{
			name:     "no clusters at all yields an empty matrix",
			results:  nil,
			wantRows: []string{},
		},
		{
			name: "a single cluster still produces a full matrix",
			results: []ClusterResult{
				scannedCluster("prod",
					passed("C-0038", "Host PID/IPC privileges"),
					failed("C-0016", "Allow privilege escalation", 3),
				),
			},
			wantRows: []string{"C-0016", "C-0038"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matrix := BuildControlMatrix(tt.results)

			got := make([]string, 0, len(matrix.Controls))
			for _, row := range matrix.Controls {
				got = append(got, row.ControlID)
			}
			require.Equal(t, tt.wantRows, got)

			if tt.assert != nil {
				tt.assert(t, matrix)
			}
		})
	}
}

// TestBuildControlMatrixOrderIsIndependentOfInput guards the sort in
// BuildControlMatrix. Control summaries live in a map, so without it the rows
// would follow Go's randomised map iteration and two reports of an unchanged
// fleet would not compare equal.
func TestBuildControlMatrixOrderIsIndependentOfInput(t *testing.T) {
	specs := []controlSpec{
		passed("C-0038", "Host PID/IPC privileges"),
		failed("C-0016", "Allow privilege escalation", 1),
		skipped("C-0260", "Missing network policy"),
		passed("C-0017", "Immutable container filesystem"),
	}
	want := []string{"C-0016", "C-0017", "C-0038", "C-0260"}

	// Repeat so a run that happened to hash in the right order cannot pass by
	// luck.
	for i := 0; i < 20; i++ {
		matrix := BuildControlMatrix([]ClusterResult{scannedCluster("prod", specs...)})

		got := make([]string, 0, len(matrix.Controls))
		for _, row := range matrix.Controls {
			got = append(got, row.ControlID)
		}
		require.Equal(t, want, got, "row order changed on iteration %d", i)
	}
}

// TestBuildControlMatrixReadsComplianceScore covers the distinction between a
// control that scored zero and one that was never scored: ControlSummary
// reports an absent compliance score as -1, and the cell has to carry that
// through rather than flattening it to 0.
func TestBuildControlMatrixReadsComplianceScore(t *testing.T) {
	matrix := BuildControlMatrix([]ClusterResult{
		scannedCluster("prod", failed("C-0016", "Allow privilege escalation", 2)),
		scannedCluster("staging", notEvaluated("C-0016", "Allow privilege escalation")),
	})

	require.Len(t, matrix.Controls, 1)
	row := matrix.Controls[0]

	assert.Equal(t, float32(0), row.ByCluster["prod"].ComplianceScore)
	assert.Equal(t, float32(-1), row.ByCluster["staging"].ComplianceScore,
		"an unscored control must not be reported as scoring zero")
}
