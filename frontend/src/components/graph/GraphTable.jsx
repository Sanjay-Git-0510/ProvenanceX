import { useMemo, useState } from "react";
import { humanize } from "../../lib/format.js";
import { isInferredEdge } from "../../lib/graphLayout.js";
import DataTable from "../ui/DataTable.jsx";
import Pagination from "../ui/Pagination.jsx";
import Panel from "../ui/Panel.jsx";

const PAGE_SIZE = 50;

function PagedTable({ title, caption, columns, rows, getRowKey, empty }) {
  const [offset, setOffset] = useState(0);
  return (
    <Panel title={title} className="span-12">
      <DataTable
        caption={caption}
        captionHidden
        columns={columns}
        rows={rows.slice(offset, offset + PAGE_SIZE)}
        getRowKey={getRowKey}
        empty={<p className="state__message">{empty}</p>}
      />
      {rows.length > PAGE_SIZE ? (
        <Pagination total={rows.length} limit={PAGE_SIZE} offset={offset} onChange={setOffset} label={`${title} pages`} />
      ) : null}
    </Panel>
  );
}

/** The keyboard and screen-reader equivalent of the drawing: every node and edge, as tables. */
export default function GraphTable({ nodes, edges, allNodes, selectedKey, onSelect, rootKey }) {
  const labels = useMemo(() => new Map(allNodes.map((node) => [node.key, node.label])), [allNodes]);

  const nodeColumns = [
    {
      key: "label",
      header: "Node",
      render: (node) => (
        <button
          type="button"
          className="graph-row-button"
          aria-pressed={node.key === selectedKey}
          onClick={() => onSelect(node.key)}
        >
          {node.label}
        </button>
      ),
    },
    { key: "type", header: "Type", render: (node) => humanize(node.type) },
    { key: "root", header: "Role", render: (node) => (node.key === rootKey ? "Root" : "Node") },
  ];
  const edgeColumns = [
    { key: "source", header: "From", render: (edge) => labels.get(edge.source) },
    { key: "relation", header: "Relation", render: (edge) => humanize(edge.relation) },
    { key: "target", header: "To", render: (edge) => labels.get(edge.target) },
    { key: "origin", header: "Origin", render: (edge) => humanize(edge.origin) },
    { key: "kind", header: "Basis", render: (edge) => (isInferredEdge(edge) ? "Inferred" : "Recorded") },
  ];

  return (
    <>
      <PagedTable
        title="Nodes"
        caption="Graph nodes"
        columns={nodeColumns}
        rows={nodes}
        getRowKey={(node) => node.key}
        empty="No nodes match these filters."
      />
      <PagedTable
        title="Edges"
        caption="Graph edges"
        columns={edgeColumns}
        rows={edges}
        getRowKey={(edge) => edge.id}
        empty="No edges match these filters."
      />
    </>
  );
}
