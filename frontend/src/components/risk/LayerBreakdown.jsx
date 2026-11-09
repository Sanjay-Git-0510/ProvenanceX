import { formatProbability, humanize } from "../../lib/format.js";
import { layerLabel } from "../../lib/policyDisplay.js";
import Badge from "../ui/Badge.jsx";
import DataTable from "../ui/DataTable.jsx";
import EvidenceLinkList from "./EvidenceLinkList.jsx";

const STATUS_TONES = { evaluated: "allow", partial: "review", not_evaluated: "unknown", not_applicable: "neutral" };

export default function LayerBreakdown({ layers, artifactType }) {
  const columns = [
    { key: "layer", header: "Layer", render: (row) => layerLabel(row.layer) },
    {
      key: "status",
      header: "Status",
      render: (row) => <Badge tone={STATUS_TONES[row.status] || "unknown"}>{humanize(row.status)}</Badge>,
    },
    { key: "score", header: "Layer score", align: "end", render: (row) => formatProbability(row.score) },
    { key: "coverage", header: "Coverage", align: "end", render: (row) => formatProbability(row.coverage) },
    { key: "contribution", header: "Contribution", align: "end", render: (row) => formatProbability(row.contribution) },
    {
      key: "evidence",
      header: "Evidence",
      render: (row) =>
        row.evidence_links?.length ? (
          <EvidenceLinkList links={row.evidence_links} artifactType={artifactType} />
        ) : (
          "None"
        ),
    },
  ];
  return (
    <DataTable
      caption="Evidence layers behind the score"
      captionHidden
      columns={columns}
      rows={layers}
      getRowKey={(row) => row.layer}
    />
  );
}
