package fleet

import (
	"time"

	"github.com/kubescape/kubescape/v3/core/cautils"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// FleetReport is the top-level aggregate: one entry per scanned context plus
// the cross-cluster views derived from them.
type FleetReport struct {
	Metadata      FleetMetadata      `json:"metadata"`
	Clusters      []ClusterResult    `json:"clusters"`
	ControlMatrix FleetControlMatrix `json:"controlMatrix"`
}

// FleetMetadata describes the run that produced the report.
type FleetMetadata struct {
	GeneratedAt      time.Time `json:"generatedAt"`
	KubescapeVersion string    `json:"kubescapeVersion,omitempty"`
	// Contexts is the requested scan set, in the order the user gave it, so a
	// consumer can tell a context that was never reached from one that was
	// never asked for.
	Contexts []string `json:"contexts"`
}

// ClusterScanStatus is the outcome of one cluster's scan.
//
// The non-scanned outcomes are kept apart because they need different
// responses. A pipeline can retry an unreachable cluster or treat it as an
// infrastructure problem; an error means the scan ran and something in it
// failed; a cancellation means nobody has learned anything about the cluster
// yet. A single "failed" value would force every consumer to parse the error
// string to tell those apart.
type ClusterScanStatus string

const (
	// ClusterScanned means the scan completed and Report is populated.
	ClusterScanned ClusterScanStatus = "scanned"
	// ClusterUnreachable means the cluster's API server could not be reached.
	ClusterUnreachable ClusterScanStatus = "unreachable"
	// ClusterError means the scan started and failed for some other reason.
	ClusterError ClusterScanStatus = "error"
	// ClusterCancelled means the run was interrupted before this cluster
	// finished, typically by a signal.
	//
	// It is deliberately not folded into ClusterUnreachable. An operator who
	// presses Ctrl-C has learned nothing about whether the cluster was
	// reachable, and reporting it as unreachable would put a claim about the
	// infrastructure into the report that the run never actually tested.
	ClusterCancelled ClusterScanStatus = "cancelled"
)

// ClusterResult wraps one cluster's PostureReport with fleet-level status.
//
// A cluster that could not be scanned still gets an entry, with Status set and
// Report nil, so it stays visible in the output instead of being dropped. An
// operator reading a fleet report needs to see that a cluster is missing;
// silently omitting it produces a report that looks complete and is not.
type ClusterResult struct {
	// ClusterID identifies the cluster across the report. It is the context
	// name for now, which is a kubeconfig label rather than a cluster identity
	// and is therefore not stable across machines. It is a separate field from
	// Context so it can carry a portable identifier later without changing the
	// shape of the report.
	ClusterID string `json:"clusterID"`
	// Context is the kubeconfig context the scan was run against.
	Context string            `json:"context"`
	Status  ClusterScanStatus `json:"status"`
	// Error is the failure that produced a non-scanned Status, kept verbatim.
	// Flattening it loses the difference between an expired credential and an
	// unroutable API server, which is exactly what the reader needs.
	Error string `json:"error,omitempty"`
	// ComplianceScore is the cluster's own score, copied out so a consumer can
	// read the summary rows without walking into Report.
	//
	// It is a pointer so that a cluster which was never scanned serialises
	// without a score at all. A plain float32 would emit 0 for an unreachable
	// cluster, which reads as "fully non-compliant" rather than "not measured"
	// and would drag down any consumer that averages the column.
	ComplianceScore *float32 `json:"complianceScore,omitempty"`
	// Coverage records how complete the scan was. A control that diverges
	// between two clusters means something different when one of them was only
	// partially scanned, so coverage travels with the result rather than being
	// looked up separately. Nil for the same reason as ComplianceScore.
	Coverage *cautils.ScanCoverage `json:"coverage,omitempty"`
	Duration string                `json:"duration,omitempty"`
	// Report is the unmodified single-cluster report. It is nil for any
	// non-scanned cluster, so every consumer has to check Status first.
	Report *reporthandlingv2.PostureReport `json:"report,omitempty"`
}

// Scanned reports whether the cluster produced a usable report. Aggregation
// starts from this rather than from Status alone, so a result that claims to
// have been scanned but carries no report is treated as missing data instead of
// being dereferenced.
//
// It guards Report only. ComplianceScore and Coverage are separate pointers and
// can still be nil on a result this returns true for, so anything reading them
// needs its own check; Scored covers the common case.
func (c *ClusterResult) Scanned() bool {
	return c.Status == ClusterScanned && c.Report != nil
}

// Scored reports whether the cluster carries the measurements a fleet-wide
// score is computed from. A scanned cluster whose score or coverage is missing
// is not a zero, it is an absence, and callers that average across clusters
// have to exclude it rather than fold a nil into the arithmetic.
func (c *ClusterResult) Scored() bool {
	return c.Scanned() && c.ComplianceScore != nil && c.Coverage != nil
}

// FleetControlMatrix is the control x cluster grid: for each control, its
// status in every cluster that was scanned.
type FleetControlMatrix struct {
	// Controls is sorted by control ID so the same inputs always render the
	// same way, in a table or in a diff of two JSON reports.
	Controls []FleetControlRow `json:"controls"`
}

// FleetControlRow is one control across the fleet.
type FleetControlRow struct {
	ControlID string `json:"controlID"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	// ByCluster is keyed by ClusterResult.ClusterID. A cluster missing from
	// this map contributed no data for this control, either because it was not
	// scanned or because the control was not in its scan set.
	ByCluster map[string]ControlStatusCell `json:"byCluster"`
}

// ControlStatusCell is one control's outcome in one cluster.
type ControlStatusCell struct {
	Status          CellStatus `json:"status"`
	FailedResources int        `json:"failedResources"`
	ComplianceScore float32    `json:"complianceScore"`
}

// CellStatus is a control's outcome in a single cluster, normalised for
// cross-cluster comparison.
//
// This is deliberately not apis.ScanningStatus. A control that could not be
// evaluated is recorded upstream as status "skipped" with sub-status
// "notEvaluated" (see OPAProcessor.markControlsSkipped), which puts it in the
// same bucket as a control skipped by an exception or as irrelevant. Those two
// mean opposite things across clusters: a skipped control agrees with a skipped
// control, whereas a control that one cluster evaluated and another did not is
// a gap in what was measured. Collapsing the pair into one value here keeps
// that distinction available to everything downstream.
type CellStatus string

const (
	CellPassed CellStatus = "passed"
	CellFailed CellStatus = "failed"
	// CellSkipped is a control that was deliberately not applied, for example
	// because an exception matched or it was irrelevant to the cluster.
	CellSkipped CellStatus = "skipped"
	// CellNotEvaluated is a control that Kubescape could not evaluate, for
	// example because a required resource type failed to collect or the
	// control timed out.
	CellNotEvaluated CellStatus = "notEvaluated"
)
