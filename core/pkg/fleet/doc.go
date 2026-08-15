// Package fleet aggregates the results of scanning several clusters into a
// single cross-cluster view.
//
// Kubescape scans one cluster per invocation and nothing in the codebase sits
// above a single reporthandlingv2.PostureReport, so questions that span
// clusters ("which clusters fail C-0016?", "staging passes this control and
// prod fails it, where did we drift?") currently have no answer other than a
// shell loop and a hand-written merge.
//
// This package holds the aggregate types and the pure functions that derive
// cross-cluster views from a slice of already-collected per-cluster results.
// It deliberately does not scan anything: it takes []ClusterResult as input,
// so every function here is testable without a cluster, and the existing
// single-cluster scan path stays untouched.
//
// # Scope
//
// What is here: the FleetReport envelope and the control matrix, which is the
// control x cluster grid the rest of the fleet view is derived from.
//
// What is not here yet, and why:
//
//   - The orchestrator that produces []ClusterResult. It re-points the
//     process-global Kubernetes client at each context in turn via
//     cautils.EnterClusterContext, which restores the previous context on the
//     way out; TestDiscoveryRefreshFollowsTheScannedCluster pins the other half
//     of that, namely that the API-group snapshot follows the cluster being
//     scanned rather than the first one initialised.
//   - Drift detection, which compares each control's cell against a baseline
//     cluster. It reads the matrix built here, so the matrix has to settle first.
//   - Concurrency. The Kubernetes client is a process-global singleton
//     (https://github.com/kubescape/kubescape/issues/2004), so two clusters
//     cannot be scanned at the same time in one process without racing on it.
//     Orchestration is sequential until that is resolved.
package fleet
