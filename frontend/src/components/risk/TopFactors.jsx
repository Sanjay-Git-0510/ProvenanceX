import { formatFeatureValue, formatProbability, humanize } from "../../lib/format.js";
import { layerLabel } from "../../lib/policyDisplay.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import DataTable from "../ui/DataTable.jsx";

/** Rule layers ranked by their contribution to the score, with their strongest signals. */
export default function TopFactors({ factors, limit }) {
  const rows = Array.isArray(factors) ? (limit ? factors.slice(0, limit) : factors) : [];
  const columns = [
    { key: "layer", header: "Layer", render: (row) => layerLabel(row.layer) },
    { key: "contribution", header: "Contribution", align: "end", render: (row) => formatProbability(row.contribution) },
    { key: "layer_score", header: "Layer score", align: "end", render: (row) => formatProbability(row.layer_score) },
    {
      key: "signals",
      header: "Top signals",
      render: (row) =>
        row.top_signals?.length
          ? row.top_signals
              .map((s) => `${humanize(sanitizeDisplay(s.name))} = ${sanitizeDisplay(formatFeatureValue(s.value))}`)
              .join("; ")
          : "None",
    },
  ];
  return (
    <DataTable
      caption="Layers ranked by contribution to the risk score"
      captionHidden
      columns={columns}
      rows={rows}
      getRowKey={(row) => row.layer}
      empty={<p className="state__message">No layer added to the score.</p>}
    />
  );
}
