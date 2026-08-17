package fleet

import (
	"sort"

	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

// BuildControlMatrix builds the control x cluster grid from per-cluster results.
//
// Only clusters with ClusterScanned status and a non-nil Report contribute
// cells. Everything else is skipped rather than represented as a zero value:
// an unreachable cluster has no opinion about whether a control passes, and
// recording one as "passed" or as an empty status would let a cluster nobody
// could reach silently improve the fleet's apparent posture.
//
// Rows are sorted by control ID. Control summaries come out of a map, so
// without sorting the same fleet would render its rows in a different order on
// every run and two JSON reports of an unchanged fleet would not compare equal.
func BuildControlMatrix(results []ClusterResult) FleetControlMatrix {
	rows := make(map[string]*FleetControlRow)

	for i := range results {
		cluster := &results[i]
		if !cluster.Scanned() {
			continue
		}

		for controlID, summary := range cluster.Report.SummaryDetails.Controls {
			row, ok := rows[controlID]
			if !ok {
				row = &FleetControlRow{
					ControlID: controlID,
					Name:      summary.GetName(),
					Severity:  apis.ControlSeverityToString(summary.GetScoreFactor()),
					ByCluster: make(map[string]ControlStatusCell),
				}
				rows[controlID] = row
			}
			row.ByCluster[cluster.ClusterID] = newControlStatusCell(summary)
		}
	}

	controls := make([]FleetControlRow, 0, len(rows))
	for _, row := range rows {
		controls = append(controls, *row)
	}
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ControlID < controls[j].ControlID
	})

	return FleetControlMatrix{Controls: controls}
}

// newControlStatusCell reads one control summary into a cell.
//
// The summary is taken by value because reportsummary.ControlSummaries stores
// values, and GetStatus has a pointer receiver that fills in StatusInfo from
// the legacy Status field, so it needs an addressable copy to work on.
func newControlStatusCell(summary reportsummary.ControlSummary) ControlStatusCell {
	return ControlStatusCell{
		Status:          cellStatus(&summary),
		FailedResources: summary.NumberOfResources().Failed(),
		ComplianceScore: summary.GetComplianceScore(),
	}
}

// cellStatus normalises a control summary into a CellStatus, separating a
// control that was skipped on purpose from one that could not be evaluated.
func cellStatus(summary *reportsummary.ControlSummary) CellStatus {
	status := summary.GetStatus()

	switch {
	case status.IsPassed():
		return CellPassed
	case status.IsFailed():
		return CellFailed
	case summary.GetSubStatus() == apis.SubStatusNotEvaluated:
		return CellNotEvaluated
	default:
		return CellSkipped
	}
}
