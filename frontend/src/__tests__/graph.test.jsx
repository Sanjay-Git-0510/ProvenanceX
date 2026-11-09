import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { MAX_CANVAS_NODES } from "../lib/graphLayout.js";
import DependencyGraph from "../pages/DependencyGraph.jsx";
import ModelLineage from "../pages/ModelLineage.jsx";
import { CANARY, HOST_PATH, SCAN_ID, mockApi, renderPage, scanList, scanRow } from "../test/helpers.jsx";

const graphBody = (overrides = {}) => ({
  scan_id: SCAN_ID,
  root_key: "root",
  graph_kind: "dependency",
  source: "syft",
  is_mock: false,
  nodes: [
    { key: "root", node_type: "artifact", label: "demo-app", component_id: null, attributes: {} },
    { key: "pkg", node_type: "package", label: "requests@2.0", component_id: null, attributes: { version: "2.0", raw_blob: CANARY } },
  ],
  edges: [{ source: "root", target: "pkg", relation: "depends_on", origin: "sbom", attributes: { raw_blob: CANARY } }],
  features: { dependency_count: 1, cvss_max: null, raw_blob: CANARY },
  limitations: [`Limited at ${HOST_PATH}`],
  stage: { status: "completed", raw_blob: CANARY },
  ...overrides,
});

afterEach(() => vi.unstubAllGlobals());

function open(body, Page = DependencyGraph, route = "/graph") {
  mockApi([
    [/\/graph$/, body],
    [/\/scans\?/, scanList([scanRow()])],
  ]);
  return renderPage(<Page />, { path: `${route}?scan=${SCAN_ID}`, route });
}

describe("graph pages", () => {
  it("draws the graph and lists the same data in tables", async () => {
    const { container } = open(graphBody());
    await screen.findByRole("table", { name: "Graph nodes" });
    expect(container.querySelectorAll("svg[role=img] g.graph-node")).toHaveLength(2);
    expect(container.querySelectorAll("path.graph-edge")).toHaveLength(1);
    expect(within(screen.getByRole("table", { name: "Graph edges" })).getByText("Depends on")).toBeInTheDocument();
    expect(screen.getByText("Root · Artifact")).toBeInTheDocument();
  });

  it("never renders raw blobs or unsanitized text", async () => {
    const { container } = open(graphBody());
    await screen.findByRole("table", { name: "Graph nodes" });
    fireEvent.click(screen.getByRole("button", { name: "requests@2.0" }));
    expect(container.innerHTML).not.toContain(CANARY);
    expect(container.innerHTML).not.toContain("/home/victim");
    expect(screen.getByText(/Limited at \[redacted\]/)).toBeInTheDocument();
  });

  it("selects a node from the keyboard-reachable table", async () => {
    open(graphBody());
    const button = await screen.findByRole("button", { name: "requests@2.0" });
    expect(button).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(button);
    expect(button).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Version")).toBeInTheDocument();
    expect(screen.getByText("Pointed to by (1)")).toBeInTheDocument();
  });

  it("selects a node from the drawing", async () => {
    const { container } = open(graphBody());
    await screen.findByRole("table", { name: "Graph nodes" });
    fireEvent.click(container.querySelectorAll("g.graph-node")[1]);
    expect(screen.getByRole("button", { name: "requests@2.0" })).toHaveAttribute("aria-pressed", "true");
  });

  it("applies filters to the drawing and the tables", async () => {
    const { container } = open(graphBody());
    await screen.findByRole("table", { name: "Graph nodes" });
    fireEvent.change(screen.getByLabelText("Search nodes"), { target: { value: "requests" } });
    expect(container.querySelectorAll("g.graph-node")).toHaveLength(1);
    expect(screen.queryByRole("table", { name: "Graph edges" })).toBeNull();
  });

  it("shows a null feature as no value, never 0", async () => {
    open(graphBody());
    const row = (await screen.findByText("Cvss max")).closest(".dl__row");
    expect(row).toHaveTextContent("No value");
  });

  it("labels mock graphs", async () => {
    open(graphBody({ source: "mock", is_mock: true }));
    expect(await screen.findByText("MOCK DATA")).toBeInTheDocument();
  });

  it("replaces the drawing above the limit and keeps the tables", async () => {
    const nodes = Array.from({ length: MAX_CANVAS_NODES + 1 }, (_, i) => ({ key: `n${i}`, node_type: "package", label: `n${i}`, attributes: {} }));
    const { container } = open(graphBody({ nodes, edges: [] }));
    expect(await screen.findByText(/too many to draw/)).toBeInTheDocument();
    expect(container.querySelector("svg[role=img]")).toBeNull();
    expect(screen.getByRole("table", { name: "Graph nodes" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Nodes pages" })).toHaveTextContent("Showing 1 to 50 of 301");
  });

  it("does not draw another kind's graph", async () => {
    const { container } = open(graphBody({ graph_kind: "lineage" }));
    expect(await screen.findByRole("link", { name: "Open model lineage" })).toHaveAttribute("href", `/lineage?scan=${SCAN_ID}`);
    expect(container.querySelector("svg[role=img]")).toBeNull();
  });

  it("draws a lineage graph on Model Lineage", async () => {
    const { container } = open(graphBody({ graph_kind: "lineage" }), ModelLineage, "/lineage");
    await screen.findByRole("table", { name: "Graph nodes" });
    expect(container.querySelector("svg[role=img]")).not.toBeNull();
  });

  it("says a missing graph is not a clean result", async () => {
    open(graphBody({ graph_kind: null, nodes: [], edges: [], stage: null }));
    expect(await screen.findByText("No graph recorded")).toBeInTheDocument();
    expect(screen.getByText(/not a clean result/)).toBeInTheDocument();
  });

  it("asks for a scan and rejects a bad id without calling /graph", async () => {
    const fetchMock = mockApi([[/\/scans\?/, scanList([])]]);
    renderPage(<DependencyGraph />, { path: "/graph?scan=nope", route: "/graph" });
    expect(await screen.findByText("Not a valid scan ID")).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(fetchMock.mock.calls.some(([url]) => url.includes("/graph"))).toBe(false);
  });

  it("shows a load error", async () => {
    mockApi([
      [/\/graph$/, { error: { code: "boom", message: "Graph failed" } }, 500],
      [/\/scans\?/, scanList([])],
    ]);
    renderPage(<DependencyGraph />, { path: `/graph?scan=${SCAN_ID}`, route: "/graph" });
    expect(await screen.findByText("Could not load the graph")).toBeInTheDocument();
  });
});
