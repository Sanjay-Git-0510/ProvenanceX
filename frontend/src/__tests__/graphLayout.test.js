import {
  MAX_CANVAS_NODES,
  applyGraphFilters,
  filterOptions,
  layoutGraph,
  namedFeatures,
  normalizeGraph,
  shortLabel,
} from "../lib/graphLayout.js";
import { CANARY, HOST_PATH } from "../test/helpers.jsx";

const node = (key, overrides = {}) => ({ key, node_type: "package", label: key, attributes: {}, ...overrides });
const edge = (source, target, overrides = {}) => ({ source, target, relation: "depends_on", origin: "sbom", ...overrides });

describe("normalizeGraph", () => {
  it("keeps named attributes and drops everything else", () => {
    const { nodes } = normalizeGraph({
      nodes: [node("a", { attributes: { name: "requests", version: "2.0", secret_blob: CANARY, nested: { x: CANARY } } })],
      edges: [],
    });
    expect(nodes[0].details.map((d) => d.field)).toEqual(["name", "version"]);
    expect(JSON.stringify(nodes)).not.toContain(CANARY);
    expect(nodes[0]).not.toHaveProperty("attributes");
  });

  it("sanitizes every text field", () => {
    const { nodes, edges } = normalizeGraph({
      nodes: [node(HOST_PATH, { label: HOST_PATH, node_type: HOST_PATH, attributes: { name: HOST_PATH } }), node("b")],
      edges: [edge(HOST_PATH, "b", { relation: HOST_PATH, origin: HOST_PATH, attributes: { confidence: HOST_PATH } })],
    });
    const { key, ...displayed } = nodes[0];
    expect(key).toBe(HOST_PATH);
    expect(JSON.stringify(displayed)).not.toContain("/home/victim");
    const { id, source, target, ...shown } = edges[0];
    expect([id, source, target].join()).toContain(HOST_PATH);
    expect(JSON.stringify(shown)).not.toContain("/home/victim");
  });

  it("rejects attribute values of the wrong type", () => {
    const { nodes } = normalizeGraph({ nodes: [node("a", { attributes: { pinned: "yes", size: "9", name: { a: 1 } } })], edges: [] });
    expect(nodes[0].details).toEqual([]);
  });

  it("keeps a false boolean and a zero size", () => {
    const { nodes } = normalizeGraph({ nodes: [node("a", { attributes: { pinned: false, size: 0 } })], edges: [] });
    expect(nodes[0].details.map((d) => d.value)).toEqual(["0", "No"]);
  });

  it("counts and drops edges to unknown nodes, and duplicate nodes", () => {
    const graph = normalizeGraph({ nodes: [node("a"), node("a")], edges: [edge("a", "missing")] });
    expect(graph.nodes).toHaveLength(1);
    expect(graph.edges).toHaveLength(0);
    expect(graph.droppedEdges).toBe(1);
  });

  it.each([null, {}, { nodes: "x", edges: 3 }])("survives malformed input %j", (data) => {
    expect(normalizeGraph(data)).toEqual({ nodes: [], edges: [], droppedEdges: 0 });
  });
});

describe("namedFeatures", () => {
  it("shows only named scalar features and keeps null", () => {
    const result = namedFeatures({ dependency_count: 0, cvss_max: null, secret: CANARY, cycles_present: { x: 1 } });
    expect(result.map((f) => [f.name, f.value])).toEqual([["dependency_count", 0], ["cvss_max", null]]);
  });
});

describe("filters", () => {
  const graph = normalizeGraph({
    nodes: [node("alpha"), node("beta", { node_type: "model" })],
    edges: [edge("alpha", "beta"), edge("beta", "alpha", { relation: "trained_on" })],
  });

  it("lists options", () => {
    expect(filterOptions(graph)).toEqual({ nodeTypes: ["model", "package"], relations: ["depends_on", "trained_on"] });
  });

  it("drops edges whose ends are filtered out", () => {
    const result = applyGraphFilters(graph, { search: "ALPHA" });
    expect(result.nodes.map((n) => n.key)).toEqual(["alpha"]);
    expect(result.edges).toEqual([]);
  });

  it("filters relations and types", () => {
    expect(applyGraphFilters(graph, { relation: "trained_on" }).edges).toHaveLength(1);
    expect(applyGraphFilters(graph, { nodeType: "model" }).nodes).toHaveLength(1);
  });
});

describe("layoutGraph", () => {
  const prepared = (nodes, edges) => normalizeGraph({ nodes, edges });

  it("positions every node and edge", () => {
    const { nodes, edges } = prepared([node("a"), node("b"), node("c")], [edge("a", "b"), edge("b", "c")]);
    const drawing = layoutGraph(nodes, edges);
    expect(drawing.nodes.every((n) => Number.isFinite(n.x) && Number.isFinite(n.y))).toBe(true);
    expect(drawing.edges.every((e) => e.points.length >= 2)).toBe(true);
    expect(drawing.width).toBeGreaterThan(0);
  });

  it("handles cycles and self references", () => {
    const { nodes, edges } = prepared([node("a"), node("b")], [edge("a", "b"), edge("b", "a"), edge("a", "a")]);
    expect(layoutGraph(nodes, edges).edges).toHaveLength(3);
  });

  it("lays out a graph at the drawing limit", () => {
    const list = Array.from({ length: MAX_CANVAS_NODES }, (_, i) => node(`n${i}`));
    const links = list.slice(1).map((n, i) => edge(`n${i}`, n.key));
    const { nodes, edges } = prepared(list, links);
    expect(layoutGraph(nodes, edges).nodes).toHaveLength(MAX_CANVAS_NODES);
  });
});

it("shortens only long labels", () => {
  expect(shortLabel("short")).toBe("short");
  expect(shortLabel("x".repeat(40), 10)).toHaveLength(10);
});
