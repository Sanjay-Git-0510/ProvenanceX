// Prepares /graph responses for display. /graph is not sanitized by the backend, so raw
// `attributes` stop here: only the named fields below, cleaned, reach a component.
import { graphlib, layout } from "@dagrejs/dagre";
import { formatCount, humanize } from "./format.js";
import { sanitizeDisplay } from "./sanitizeDisplay.js";

/** Above this many visible nodes the drawing is replaced by a notice; the tables stay complete. */
export const MAX_CANVAS_NODES = 300;
export const NODE_WIDTH = 208;
export const NODE_HEIGHT = 48;

const yesNo = (value) => (typeof value === "boolean" ? (value ? "Yes" : "No") : null);
const count = (value) => (typeof value === "number" && Number.isFinite(value) ? formatCount(value) : null);
const text = (value) => (typeof value === "string" && value ? sanitizeDisplay(value) : null);

const NODE_FIELDS = [
  ["name", "Name", text],
  ["version", "Version", text],
  ["purl", "Package URL", text],
  ["ecosystem", "Ecosystem", text],
  ["artifact_type", "Artifact type", text],
  ["declared_revision", "Declared revision", text],
  ["peft_type", "Adapter type", text],
  ["serialization", "Serialization", text],
  ["downloaded", "Downloaded", yesNo],
  ["size", "Size (bytes)", count],
  ["pinned", "Version pinned", yesNo],
];

/** Graph features shown by name. Anything else in `features` is not displayed. */
export const FEATURE_NAMES = [
  "dependency_count",
  "direct_dependency_count",
  "transitive_dependency_count",
  "transitive_depth",
  "transitive_resolution",
  "node_count",
  "edge_count",
  "sbom_edge_count",
  "inferred_edge_count",
  "max_degree_centrality",
  "max_betweenness_centrality",
  "betweenness_approximate",
  "cycles_present",
  "vulnerable_count",
  "vulnerability_count",
  "cvss_max",
  "base_model_count",
  "dataset_count",
  "adapter_present",
];

function namedDetails(attributes) {
  if (!attributes || typeof attributes !== "object") return [];
  return NODE_FIELDS.flatMap(([field, label, format]) => {
    const value = format(attributes[field]);
    return value === null ? [] : [{ field, label, value }];
  });
}

/** Valid nodes and edges with display-safe text. An edge to an unknown node is counted and dropped. */
export function normalizeGraph(data) {
  const seen = new Set();
  const nodes = [];
  (Array.isArray(data?.nodes) ? data.nodes : []).forEach((node) => {
    if (typeof node?.key !== "string" || seen.has(node.key)) return;
    seen.add(node.key);
    nodes.push({
      key: node.key,
      displayKey: sanitizeDisplay(node.key),
      label: sanitizeDisplay(node.label) || sanitizeDisplay(node.key),
      type: sanitizeDisplay(node.node_type) || "unknown",
      details: namedDetails(node.attributes),
    });
  });

  const edges = [];
  let droppedEdges = 0;
  (Array.isArray(data?.edges) ? data.edges : []).forEach((edge) => {
    if (!seen.has(edge?.source) || !seen.has(edge?.target)) {
      droppedEdges += 1;
      return;
    }
    edges.push({
      id: `${edge.source}\u0000${edge.target}`,
      source: edge.source,
      target: edge.target,
      relation: sanitizeDisplay(edge.relation) || "unknown",
      origin: sanitizeDisplay(edge.origin) || "unknown",
      confidence: text(edge.attributes?.confidence),
    });
  });
  return { nodes, edges, droppedEdges };
}

/** The named features that hold a single value. A null stays null, meaning no value. */
export function namedFeatures(features) {
  if (!features || typeof features !== "object") return [];
  return FEATURE_NAMES.flatMap((name) => {
    if (!Object.hasOwn(features, name)) return [];
    const value = features[name];
    if (value !== null && !["string", "number", "boolean"].includes(typeof value)) return [];
    return [{ name, label: humanize(name), value: typeof value === "string" ? sanitizeDisplay(value) : value }];
  });
}

const distinct = (values) => [...new Set(values)].sort((a, b) => a.localeCompare(b));

export function filterOptions({ nodes, edges }) {
  return { nodeTypes: distinct(nodes.map((n) => n.type)), relations: distinct(edges.map((e) => e.relation)) };
}

/** Filters apply to the drawing and the tables alike, so the two never disagree. */
export function applyGraphFilters({ nodes, edges }, { search = "", nodeType = "", relation = "" } = {}) {
  const term = search.trim().toLowerCase();
  const visible = nodes.filter(
    (node) => (!nodeType || node.type === nodeType) && (!term || node.label.toLowerCase().includes(term)),
  );
  const keys = new Set(visible.map((node) => node.key));
  return {
    nodes: visible,
    edges: edges.filter(
      (edge) => keys.has(edge.source) && keys.has(edge.target) && (!relation || edge.relation === relation),
    ),
  };
}

export function isInferredEdge(edge) {
  return edge.origin.startsWith("inferred");
}

/** Keeps one line of an SVG label inside its box. The full label is in the node's tooltip. */
export function shortLabel(label, max = 28) {
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

/** Left-to-right positions from dagre. Throws if the layout fails; the caller shows the tables. */
export function layoutGraph(nodes, edges) {
  const graph = new graphlib.Graph();
  graph.setGraph({ rankdir: "LR", nodesep: 16, ranksep: 64, marginx: 16, marginy: 16 });
  graph.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((node) => graph.setNode(node.key, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  edges.forEach((edge) => graph.setEdge(edge.source, edge.target));
  layout(graph);

  const size = graph.graph();
  return {
    width: size.width,
    height: size.height,
    nodes: nodes.map((node) => {
      const { x, y } = graph.node(node.key);
      return { ...node, x: x - NODE_WIDTH / 2, y: y - NODE_HEIGHT / 2 };
    }),
    edges: edges.map((edge) => ({
      ...edge,
      points: graph
        .edge(edge.source, edge.target)
        .points.filter((point) => Number.isFinite(point.x) && Number.isFinite(point.y)),
    })),
  };
}
