import { useCallback } from "react";
import { Link } from "react-router-dom";
import useApi from "../../hooks/useApi.js";
import { formatDateTime, formatRelativeTime, formatRiskScore, humanize } from "../../lib/format.js";
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
    width: "28%",
    render: (row) => {
      const name = sanitizeDisplay(row.artifact.name);
      return (
        <Link className="cell-truncate" to={`/scans/${row.scan_id}`} title={name}>
          {name}
        </Link>
      );
    },
  },
  { key: "type", header: "Type", width: "11%", render: (row) => humanize(row.artifact.artifact_type) },
  { key: "status", header: "Status", width: "14%", render: (row) => <ScanStatusBadge status={row.status} /> },
  { key: "risk", header: "Risk", align: "end", width: "10%", render: (row) => formatRiskScore(row.risk_score) },
  { key: "decision", header: "Decision", width: "22%", render: (row) => <RowDecision scan={row} /> },
  {
    key: "created",
    header: "Started",
    width: "15%",
    render: (row) => <time dateTime={row.created_at} title={formatDateTime(row.created_at)}>{formatRelativeTime(row.created_at)}</time>,
  },
];

export default function RecentScansTable({ scans, empty }) {
  return (
    <DataTable
      caption="Table of recent scans"
      captionHidden
      columns={columns}
      rows={scans}
      getRowKey={(row) => row.scan_id}
      empty={empty}
      compact
    />
  );
}
