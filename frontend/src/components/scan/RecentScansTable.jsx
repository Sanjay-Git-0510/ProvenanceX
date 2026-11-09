import { useCallback } from "react";
import { Link } from "react-router-dom";
import useApi from "../../hooks/useApi.js";
import { formatDateTime, formatRiskScore, humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import { api } from "../../services/api.js";
import DecisionDisplay from "../risk/DecisionDisplay.jsx";
import DataTable from "../ui/DataTable.jsx";
import ScanStatusBadge from "./ScanStatusBadge.jsx";

/**
 * /scans has no layer list, so an ALLOW row reads it from /risk. An ALLOW always has a stored
 * decision, so this only reads. Other rows never call /risk, which could compute a new result.
 */
function RowDecision({ scan }) {
  const fetcher = useCallback((options) => api.getRisk(scan.scan_id, options), [scan.scan_id]);
  const risk = useApi(scan.decision === "ALLOW" ? fetcher : null);
  return (
    <DecisionDisplay
      decision={scan.decision}
      confidence={scan.confidence}
      confidenceLabel={risk.data?.confidence_label}
      notEvaluatedLayers={risk.data?.not_evaluated_layers}
      layersNote={risk.status === "error" ? "could not be loaded" : "loading"}
    />
  );
}

const columns = [
  {
    key: "artifact",
    header: "Artifact",
    render: (row) => <Link to={`/scans/${row.scan_id}`}>{sanitizeDisplay(row.artifact.name)}</Link>,
  },
  { key: "type", header: "Type", render: (row) => humanize(row.artifact.artifact_type) },
  { key: "status", header: "Status", render: (row) => <ScanStatusBadge status={row.status} /> },
  { key: "risk", header: "ProvenanceX risk", align: "end", render: (row) => formatRiskScore(row.risk_score) },
  { key: "decision", header: "Decision", render: (row) => <RowDecision scan={row} /> },
  { key: "created", header: "Started", render: (row) => formatDateTime(row.created_at) },
];

export default function RecentScansTable({ scans, empty }) {
  return (
    <DataTable
      caption="Recent scans"
      captionHidden
      columns={columns}
      rows={scans}
      getRowKey={(row) => row.scan_id}
      empty={empty}
    />
  );
}
