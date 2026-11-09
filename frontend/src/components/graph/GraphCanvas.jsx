import { useMemo } from "react";
import { humanize } from "../../lib/format.js";
import {
  MAX_CANVAS_NODES,
  NODE_HEIGHT,
  NODE_WIDTH,
  isInferredEdge,
  layoutGraph,
  shortLabel,
} from "../../lib/graphLayout.js";

const ARROW_ID = "graph-arrow";

function computeLayout(nodes, edges) {
  try {
    return { drawing: layoutGraph(nodes, edges), failed: false };
  } catch (error) {
    console.error("Graph layout failed", error);
    return { drawing: null, failed: true };
  }
}

function edgePath(points) {
  return points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x} ${point.y}`).join(" ");
}

/**
 * The SVG drawing, for pointer users. It is one labelled image to assistive technology:
 * GraphTable is the keyboard and screen-reader equivalent.
 */
export default function GraphCanvas({ nodes, edges, rootKey, selectedKey, onSelect, zoom, title }) {
  const tooLarge = nodes.length > MAX_CANVAS_NODES;
  const result = useMemo(
    () => (nodes.length === 0 || tooLarge ? null : computeLayout(nodes, edges)),
    [nodes, edges, tooLarge],
  );

  if (tooLarge) {
    return (
      <p className="state__message">
        {nodes.length} nodes match, which is too many to draw (limit {MAX_CANVAS_NODES}). Narrow the filters, or use the
        complete tables below.
      </p>
    );
  }
  if (nodes.length === 0) return <p className="state__message">No nodes match these filters.</p>;
  if (result.failed) {
    return <p className="state__message">This graph could not be drawn. The tables below still list its data.</p>;
  }

  const { drawing } = result;
  return (
    <div className="graph-canvas" role="region" aria-label={`${title} drawing, scrollable`} tabIndex={0}>
      <svg
        role="img"
        aria-label={`${title}: ${nodes.length} nodes and ${edges.length} edges. The tables on this page list the same data.`}
        width={drawing.width * zoom}
        height={drawing.height * zoom}
        viewBox={`0 0 ${drawing.width} ${drawing.height}`}
      >
        <defs>
          <marker id={ARROW_ID} viewBox="0 0 8 8" refX="8" refY="4" markerWidth="8" markerHeight="8" orient="auto">
            <path className="graph-arrow" d="M0 0 L8 4 L0 8 Z" />
          </marker>
        </defs>
        {drawing.edges.map((edge) => (
          <path
            key={edge.id}
            className={`graph-edge${isInferredEdge(edge) ? " graph-edge--inferred" : ""}`}
            d={edgePath(edge.points)}
            markerEnd={`url(#${ARROW_ID})`}
          >
            <title>{`${edge.relation} (${edge.origin})`}</title>
          </path>
        ))}
        {drawing.nodes.map((node) => {
          const isRoot = node.key === rootKey;
          const classes = ["graph-node", isRoot && "graph-node--root", node.key === selectedKey && "graph-node--selected"]
            .filter(Boolean)
            .join(" ");
          return (
            <g key={node.key} className={classes} transform={`translate(${node.x} ${node.y})`} onClick={() => onSelect(node.key)}>
              <title>{`${node.label} (${humanize(node.type)})`}</title>
              <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="8" />
              <text className="graph-node__label" x="12" y="20">
                {shortLabel(node.label)}
              </text>
              <text className="graph-node__type" x="12" y="37">
                {isRoot ? `Root · ${humanize(node.type)}` : humanize(node.type)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
