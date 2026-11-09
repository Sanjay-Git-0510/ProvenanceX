import { useMemo, useState } from "react";
import { ArrowUpRight } from "lucide-react";
import useGraph from "../../hooks/useGraph.js";
import useScanSelection from "../../hooks/useScanSelection.js";
import { formatFeatureValue, humanize } from "../../lib/format.js";
import { MAX_CANVAS_NODES, applyGraphFilters, filterOptions, namedFeatures } from "../../lib/graphLayout.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import EmptyState from "../EmptyState.jsx";
import ScanPicker from "../scan/ScanPicker.jsx";
import Button from "../ui/Button.jsx";
import ErrorState from "../ui/ErrorState.jsx";
import LoadingState from "../ui/LoadingState.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import Panel from "../ui/Panel.jsx";
import GraphCanvas from "./GraphCanvas.jsx";
import GraphControls, { ZOOM } from "./GraphControls.jsx";
import GraphLegend from "./GraphLegend.jsx";
import GraphTable from "./GraphTable.jsx";
import NodeInspector from "./NodeInspector.jsx";

const KINDS = {
  dependency: { title: "Dependency graph", other: "/lineage", otherLabel: "Open model lineage" },
  lineage: { title: "Model lineage", other: "/graph", otherLabel: "Open dependency graph" },
};

const NO_FILTERS = { search: "", nodeType: "", relation: "" };

function GraphExplorer({ data, graph, kind }) {
  const [filters, setFilters] = useState(NO_FILTERS);
  const [selectedKey, setSelectedKey] = useState(null);
  const [zoom, setZoom] = useState(1);

  const options = useMemo(() => filterOptions(graph), [graph]);
  const visible = useMemo(() => applyGraphFilters(graph, filters), [graph, filters]);
  const features = namedFeatures(data.features);
  const { title } = KINDS[kind];
  const canDraw = visible.nodes.length > 0 && visible.nodes.length <= MAX_CANVAS_NODES;

  return (
    <>
      <GraphControls
        filters={filters}
        options={options}
        onChange={(change) => setFilters((current) => ({ ...current, ...change }))}
        zoom={zoom}
        onZoom={(value) => setZoom(Math.min(ZOOM.max, Math.max(ZOOM.min, value)))}
        showZoom={canDraw}
      />
      <div className="bento">
        <Panel title={title} className="span-8" actions={<MockLabel source={data.source} isMock={data.is_mock} />}>
          <GraphCanvas
            nodes={visible.nodes}
            edges={visible.edges}
            rootKey={data.root_key}
            selectedKey={selectedKey}
            onSelect={setSelectedKey}
            zoom={zoom}
            title={title}
          />
          <div className="panel__section">
            <GraphLegend />
          </div>
          {graph.droppedEdges > 0 ? (
            <p className="state__message panel__section">
              {graph.droppedEdges} edges point to nodes that are not in this graph and are not shown.
            </p>
          ) : null}
        </Panel>
        <Panel title="Node details" className="span-4">
          <NodeInspector graph={graph} selectedKey={selectedKey} rootKey={data.root_key} />
        </Panel>
        <GraphTable
          key={`${filters.search}|${filters.nodeType}|${filters.relation}`}
          nodes={visible.nodes}
          edges={visible.edges}
          allNodes={graph.nodes}
          selectedKey={selectedKey}
          onSelect={setSelectedKey}
          rootKey={data.root_key}
        />
        <Panel title="Graph features" eyebrow="No value means not measured" className="span-6">
          {features.length ? (
            <dl className="dl">
              {features.map(({ name, label, value }) => (
                <div className="dl__row" key={name}>
                  <dt>{label}</dt>
                  <dd>{formatFeatureValue(value)}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="state__message">No graph features were recorded.</p>
          )}
        </Panel>
        <Panel title="Limitations" className="span-6">
          <Limitations items={data.limitations} />
        </Panel>
      </div>
    </>
  );
}

function Limitations({ items }) {
  if (!Array.isArray(items) || items.length === 0) {
    return <p className="state__message">The graph stage reported no limitations.</p>;
  }
  return (
    <ul className="reason-list">
      {items.map((item, index) => (
        <li key={index}>{sanitizeDisplay(item)}</li>
      ))}
    </ul>
  );
}

function GraphResult({ scanId, kind }) {
  const { status, data, graph, error, reload } = useGraph(scanId);
  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load the graph" />;
  if (!data) return <LoadingState label="Loading the graph" />;

  const { other, otherLabel } = KINDS[kind];
  if (data.graph_kind && data.graph_kind !== kind) {
    return (
      <EmptyState
        title={`This scan has a ${sanitizeDisplay(data.graph_kind)} graph`}
        message="It is shown on its own page."
        headingLevel={2}
        action={
          <Button variant="secondary" icon={ArrowUpRight} to={`${other}?scan=${scanId}`}>
            {otherLabel}
          </Button>
        }
      />
    );
  }
  if (!data.graph_kind || graph.nodes.length === 0) {
    const stageStatus = sanitizeDisplay(data.stage?.status);
    return (
      <EmptyState
        title="No graph recorded"
        message={`${
          stageStatus ? `Graph stage status: ${humanize(stageStatus)}.` : "The graph stage has not run for this scan."
        } No graph is missing evidence, not a clean result.`}
        headingLevel={2}
      />
    );
  }
  return <GraphExplorer data={data} graph={graph} kind={kind} />;
}

/** The whole page for either graph type; the two differ only in `kind` and their text. */
export default function GraphPage({ title, lede, kind }) {
  const { scanId, invalid, selectScan } = useScanSelection();
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{title}</h1>
          <p className="page-head__lede">{lede}</p>
        </div>
      </header>
      <div className="toolbar">
        <ScanPicker scanId={scanId} onSelect={selectScan} />
      </div>
      {invalid ? <EmptyState title="Not a valid scan ID" message="Choose a scan from the list." headingLevel={2} /> : null}
      {!scanId && !invalid ? (
        <EmptyState title="Choose a scan" message="Graphs are shown per scan." headingLevel={2} />
      ) : null}
      {scanId ? <GraphResult key={scanId} scanId={scanId} kind={kind} /> : null}
    </>
  );
}
