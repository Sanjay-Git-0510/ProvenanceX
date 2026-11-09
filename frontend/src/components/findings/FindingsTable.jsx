import { useState } from "react";
import { formatCvss, humanize, NOT_AVAILABLE } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import EmptyState from "../EmptyState.jsx";
import Button from "../ui/Button.jsx";
import DataTable from "../ui/DataTable.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import FindingCategoryBadge, { categoryLabel, SeverityBadge } from "./FindingCategoryBadge.jsx";
import FindingDrawer from "./FindingDrawer.jsx";

/** An empty list only means "nothing found" if the stage behind it actually completed. */
export function FindingsEmpty({ stages, category, filtered = false }) {
  const relevant = category ? [[category, stages?.[category]]] : Object.entries(stages || {});
  const incomplete = relevant.filter(([, stage]) => stage && stage.status !== "completed");
  if (incomplete.length > 0) {
    const names = incomplete
      .map(([name, stage]) => `${categoryLabel(name)} (${humanize(sanitizeDisplay(stage.status))})`)
      .join(", ");
    return (
      <EmptyState
        title="No findings listed, and evidence is incomplete"
        message={`These stages did not complete: ${names}. An empty list here does not mean nothing is wrong.`}
        headingLevel={3}
      />
    );
  }
  return (
    <EmptyState
      title="No findings"
      message={filtered ? "No findings match these filters." : "The completed stages reported no findings."}
      headingLevel={3}
    />
  );
}

export default function FindingsTable({ caption, findings, empty }) {
  const [selected, setSelected] = useState(null);
  const columns = [
    { key: "identifier", header: "Identifier", mono: true, render: (row) => sanitizeDisplay(row.identifier) },
    { key: "category", header: "Kind", render: (row) => <FindingCategoryBadge category={row.category} /> },
    { key: "title", header: "Title", render: (row) => sanitizeDisplay(row.title) || NOT_AVAILABLE },
    {
      key: "component",
      header: "Component",
      render: (row) => sanitizeDisplay(row.component?.name) || "None",
    },
    { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "cvss", header: "CVSS (advisory)", align: "end", render: (row) => formatCvss(row.cvss?.score) },
    {
      key: "source",
      header: "Source",
      render: (row) => (
        <>
          {sanitizeDisplay(row.source)} <MockLabel source={row.source} isMock={row.is_mock} />
        </>
      ),
    },
    {
      key: "open",
      header: "Details",
      render: (row) => (
        <Button
          variant="ghost"
          size="small"
          aria-label={`Open details for ${sanitizeDisplay(row.identifier)}`}
          onClick={() => setSelected(row)}
        >
          Open
        </Button>
      ),
    },
  ];
  return (
    <>
      <DataTable
        caption={caption}
        captionHidden
        columns={columns}
        rows={findings}
        getRowKey={(row) => row.finding_id}
        empty={empty}
      />
      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </>
  );
}
