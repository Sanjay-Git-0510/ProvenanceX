// Structural accessibility through jest-axe. jsdom cannot measure colour contrast or layout:
// contrast is covered by tokens.contrast.test.js, and responsive layout needs a real browser.
import { act, fireEvent, render, screen } from "@testing-library/react";
import { axe, toHaveNoViolations } from "jest-axe";
import { MemoryRouter } from "react-router-dom";
import App from "../App.jsx";
import { routes } from "../routes.js";
import { SCAN_ID, SHA, evidence, findingsPage, finding, mockApi, riskResult, scanList, scanRow } from "../test/helpers.jsx";

expect.extend(toHaveNoViolations);

const future = { v7_startTransition: true, v7_relativeSplatPath: true };

afterEach(() => vi.unstubAllGlobals());

const graph = {
  scan_id: SCAN_ID,
  root_key: "root",
  graph_kind: "dependency",
  source: "syft",
  is_mock: false,
  nodes: [
    { key: "root", node_type: "artifact", label: "demo-app", attributes: {} },
    { key: "pkg", node_type: "package", label: "requests", attributes: { version: "2.0" } },
  ],
  edges: [{ source: "root", target: "pkg", relation: "depends_on", origin: "sbom" }],
  features: { dependency_count: 1 },
  limitations: [],
  stage: { status: "completed" },
};

const verification = {
  state: "MISMATCH",
  reason: { code: "evidence_mismatch", message: "Changed: artifact_hash" },
  source: "web3",
  is_mock: false,
  fields: [{ field: "artifact_hash", stored: SHA, source_table: SHA, recomputed: SHA, chain: SHA, status: "mismatch", detail: "The values differ" }],
  missing_evidence: [],
  verified_at: "2026-11-09T07:06:00Z",
  note: "A note",
};

function stubApi() {
  mockApi([
    [/\/verify$/, verification],
    [/\/graph$/, graph],
    [/\/blockchain$/, { anchor_recorded: false, record: null, note: "Stored data only." }],
    [/\/risk$/, riskResult()],
    [/\/evidence/, evidence()],
    [/\/findings/, findingsPage([finding()])],
    [/\/scans\?/, scanList([scanRow()])],
    [/\/health\/ready$/, { status: "ready", db: "ok", version: "0.1.0" }],
    [/\/health$/, { status: "ok", version: "0.1.0" }],
  ]);
}

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]} future={future}>
      <App />
    </MemoryRouter>,
  );
}

const settle = () => act(() => new Promise((done) => setTimeout(done, 50)));

const toPath = (route) => {
  if (route === "/scans/:scanId") return `/scans/${SCAN_ID}`;
  return route === "/scans/new" || route === "/" ? route : `${route}?scan=${SCAN_ID}`;
};

describe("accessibility", () => {
  it.each(routes.map((route) => [route.label, toPath(route.path)]))("%s has no axe violations", async (_, path) => {
    stubApi();
    const { container } = renderAt(path);
    await settle();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("a selected graph node has no axe violations", async () => {
    stubApi();
    const { container } = renderAt(`/graph?scan=${SCAN_ID}`);
    fireEvent.click(await screen.findByRole("button", { name: "requests" }));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("a verification result has no axe violations", async () => {
    stubApi();
    const { container } = renderAt(`/blockchain?scan=${SCAN_ID}`);
    fireEvent.click(await screen.findByRole("button", { name: "Verify" }));
    await screen.findByText("evidence_mismatch");
    expect(await axe(container)).toHaveNoViolations();
  });
});
