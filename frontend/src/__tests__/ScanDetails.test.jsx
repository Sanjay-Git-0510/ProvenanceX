import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import ScanDetails from "../pages/ScanDetails.jsx";
import {
  CANARY,
  HOST_PATH,
  SCAN_B,
  SCAN_ID,
  SHA,
  calledUrls,
  evidence,
  expectEveryAllowHasCaveat,
  finding,
  findingsPage,
  mockApi,
  noRisk,
  renderPage,
  riskResult,
} from "../test/helpers.jsx";

afterEach(() => vi.unstubAllGlobals());

function open({ scan = evidence(), risk = riskResult(), findings = findingsPage([finding()]), id = SCAN_ID } = {}) {
  const fetchMock = mockApi([
    [/\/evidence/, scan],
    [/\/risk$/, risk],
    [/\/findings/, findings],
  ]);
  const view = renderPage(<ScanDetails />, { path: `/scans/${id}`, route: "/scans/:scanId" });
  return { fetchMock, ...view };
}

const hero = () => screen.findByRole("region", { name: "Scan summary" });

describe("Scan Details", () => {
  it("shows every required evidence section", async () => {
    open();
    for (const name of [
      "Artifact identity and integrity",
      "Evidence summary",
      "Known vulnerability findings",
      "Suspicious: static findings",
      "Suspicious: behavioral findings",
      "Provenance",
      "Timeline",
      "Why this score?",
      "Dependency graph",
      "Blockchain verification",
    ]) {
      expect(await screen.findByRole("region", { name })).toBeInTheDocument();
    }
  });

  it("uses glass on the hero and solid surfaces for hashes", async () => {
    open();
    const summary = await hero();
    expect(summary).toHaveClass("glass");
    expect(within(summary).queryByText(SHA)).toBeNull();
    const identity = screen.getByRole("region", { name: "Artifact identity and integrity" });
    expect(within(identity).getByText(SHA).closest(".glass")).toBeNull();
  });

  it("gives an ALLOW its not-evaluated layers and confidence", async () => {
    const { container } = open();
    const summary = await hero();
    await waitFor(() => expect(summary).toHaveTextContent("Not evaluated: Vulnerability, Behavioral"));
    expect(summary).toHaveTextContent("Confidence: 0.61 (MEDIUM)");
    expect(summary).toHaveTextContent("crosses 0.60");
    expectEveryAllowHasCaveat(container);
  });

  it("shows a null score beside a real decision", async () => {
    open({
      risk: riskResult({
        status: "not_computed",
        risk_score: null,
        decision: "REVIEW",
        reason: { code: "no_rule_layer_scored", message: "No rule layer could be scored" },
      }),
    });
    const summary = await hero();
    await within(summary).findByText("REVIEW");
    expect(summary).toHaveTextContent("Not computed yet");
    expect(summary).toHaveTextContent("No rule layer could be scored");
    expect(summary.querySelector(".metric__value")).not.toHaveTextContent(/\d/);
  });

  it("shows a null decision as not computed yet", async () => {
    open({ risk: noRisk("not_computed", "scan_failed", "The scan failed") });
    const summary = await hero();
    await waitFor(() => expect(summary).toHaveTextContent("The scan failed"));
    expect(within(summary).getAllByText("Not computed yet").length).toBeGreaterThan(0);
    expect(summary).not.toHaveTextContent(/ALLOW|REVIEW|BLOCK/);
  });

  it("reads only, with no write other than the existing GET /risk", async () => {
    const { fetchMock } = open();
    await screen.findByText("Why this score?");
    fetchMock.mock.calls.forEach(([, options]) => expect(options?.method).toBeUndefined());
    calledUrls(fetchMock).forEach((url) => {
      expect(url).toMatch(/\/(evidence\?|risk$|findings\?)/);
      expect(url).not.toMatch(/verify|anchor/);
    });
    expect(calledUrls(fetchMock)).not.toContain(`/api/v1/scans/${SCAN_ID}`);
  });

  it("does not call /risk or /findings while the scan runs, and says so", async () => {
    const { fetchMock } = open({ scan: evidence({ scan_status: "running" }) });
    const summary = await hero();
    expect(summary).toHaveTextContent("Running");
    expect(summary).toHaveTextContent("Pending");
    expect(summary).toHaveTextContent("The scan is still running.");
    expect(calledUrls(fetchMock).some((url) => /\/(risk|findings)/.test(url))).toBe(false);
  });

  it("shows hashes as text and gives reasons for missing ones", async () => {
    open();
    expect(await screen.findByText(SHA)).toBeInTheDocument();
    expect(screen.getByText("No SBOM was produced")).toBeInTheDocument();
  });

  it("does not display a malformed hash", async () => {
    const scan = evidence();
    scan.hashes.artifact_sha256.value = "<img src=x>";
    const { container } = open({ scan });
    expect(await screen.findAllByText("Invalid format")).toHaveLength(1);
    expect(container.querySelector("img")).toBeNull();
  });

  it.each([
    [true, "HASH CHANGED"],
    [false, "Unchanged"],
    [null, "Not determined"],
  ])("shows hash_changed %s as text", async (value, text) => {
    const scan = evidence();
    scan.provenance.hash_changed = value;
    open({ scan });
    expect(await screen.findByText(new RegExp(text))).toBeInTheDocument();
  });

  it("keeps null provenance values as undetermined", async () => {
    open();
    const row = (await screen.findByText("Signature verified")).closest(".dl__row");
    expect(row).toHaveTextContent("Could not be determined");
  });

  it("links to the dependency graph and blockchain views for software", async () => {
    open();
    expect(await screen.findByRole("link", { name: "Open dependency graph" })).toHaveAttribute("href", `/graph?scan=${SCAN_ID}`);
    expect(screen.getByRole("link", { name: "Open blockchain evidence" })).toHaveAttribute("href", `/blockchain?scan=${SCAN_ID}`);
  });

  it("links to the lineage view for a model", async () => {
    const scan = evidence();
    scan.artifact.artifact_type = "lora";
    open({ scan });
    expect(await screen.findByRole("link", { name: "Open model lineage" })).toHaveAttribute("href", `/lineage?scan=${SCAN_ID}`);
  });

  it("says what VERIFIED means and never verifies by itself", async () => {
    const { fetchMock } = open();
    const panel = await screen.findByRole("region", { name: "Blockchain verification" });
    expect(panel).toHaveTextContent("not that the scanner was correct");
    expect(calledUrls(fetchMock).join()).not.toContain("verify");
  });

  it("links a source only for an allowlisted https address", async () => {
    const scan = evidence();
    scan.artifact.source_url = "javascript:alert(1)";
    open({ scan });
    await hero();
    expect(screen.queryByRole("link", { name: /alert/ })).toBeNull();
  });

  it("labels mock evidence", async () => {
    open({ scan: evidence({ mock: { contains_mock_evidence: true, mock_stages: ["sbom"], mock_findings: 1, mock_components: 0, provenance_is_mock: false } }) });
    expect(within(await hero()).getByText("CONTAINS MOCK EVIDENCE")).toBeInTheDocument();
  });

  it("labels a mock stage and a mock finding", async () => {
    const scan = evidence();
    scan.stages[0] = { ...scan.stages[0], source: "mock", is_mock: true };
    open({ scan, findings: findingsPage([finding({ source: "mock", is_mock: true })]) });
    const timeline = await screen.findByRole("region", { name: "Timeline" });
    expect(within(timeline).getByText("MOCK DATA")).toBeInTheDocument();
    const vulnerabilities = screen.getByRole("region", { name: "Known vulnerability findings" });
    expect(await within(vulnerabilities).findByText("MOCK DATA")).toBeInTheDocument();
  });

  it("keeps CVSS, ML probability and risk separate", async () => {
    const { container } = open();
    await screen.findByText("Why this score?");
    expect(container.querySelector('[data-score="provenancex_risk"]')).toHaveTextContent("0.300");
    expect(container.querySelector('[data-score="cvss_max"]')).toHaveTextContent("7.5");
    expect(container.querySelector('[data-score="ml_probability"]')).toHaveTextContent("0.465");
  });

  it("shows the training-data notice beside ML output", async () => {
    open();
    expect(await screen.findByText("Models were trained on synthetic data.")).toBeInTheDocument();
  });

  it("does not show raw details and redacts artifact text", async () => {
    const { container } = open({ findings: findingsPage([finding({ title: `Hit ${HOST_PATH}` })]) });
    await screen.findAllByText(/Hit \[redacted\]/);
    expect(container).not.toHaveTextContent(CANARY);
    expect(container).not.toHaveTextContent(HOST_PATH);
  });

  it("explains an empty list from a stage that did not complete", async () => {
    open({ findings: findingsPage([], { stages: { vulnerability: { status: "unavailable" } } }) });
    const panel = await screen.findByRole("region", { name: "Known vulnerability findings" });
    expect(await within(panel).findByText(/does not mean nothing is wrong/)).toBeInTheDocument();
  });

  it("shows how much of a list the preview covers, and links to the rest", async () => {
    open({ findings: findingsPage([finding()], { total: 12 }) });
    const panel = await screen.findByRole("region", { name: "Known vulnerability findings" });
    expect(await within(panel).findByText("Showing 1 of 12")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "View all" })).toHaveAttribute(
      "href",
      `/findings?scan=${SCAN_ID}&category=vulnerability`,
    );
  });

  it("orders the timeline by time, not by stage name", async () => {
    const base = { source: "x", is_mock: false, incomplete_reasons: [], limitations: [], warnings: [] };
    const scan = evidence({
      stages: [
        { ...base, name: "aibom", status: "completed", started_at: "2026-11-09T07:05:30Z" },
        { ...base, name: "graph", status: "completed", started_at: "2026-11-09T07:05:10Z" },
        { ...base, name: "sandbox", status: "skipped" },
      ],
    });
    open({ scan });
    const timeline = await screen.findByRole("region", { name: "Timeline" });
    expect(within(timeline).getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual(["Graph", "Aibom", "Sandbox"]);
  });

  it("shows a failed scan's sanitized reason", async () => {
    open({
      scan: evidence({ scan_status: "failed", scan_error: { code: "ingest_failed", message: "Clone failed" } }),
      risk: noRisk("not_computed", "scan_failed", "The scan failed"),
    });
    expect(await screen.findByText("Clone failed")).toBeInTheDocument();
  });

  it("explains a /risk failure without inventing a result", async () => {
    mockApi([
      [/\/evidence/, evidence()],
      [/\/risk$/, { error: { code: "down", message: "Risk unavailable" } }, 503],
      [/\/findings/, findingsPage([])],
    ]);
    renderPage(<ScanDetails />, { path: `/scans/${SCAN_ID}`, route: "/scans/:scanId" });
    expect(await screen.findByText("Risk unavailable")).toBeInTheDocument();
    expect(await hero()).not.toHaveTextContent(/ALLOW|REVIEW|BLOCK/);
  });

  it("shows loading", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderPage(<ScanDetails />, { path: `/scans/${SCAN_ID}`, route: "/scans/:scanId" });
    expect(screen.getByText("Loading scan evidence")).toBeInTheDocument();
  });

  it("shows an error and offers no retry for a 404", async () => {
    mockApi([[/\/evidence/, { error: { code: "scan_not_found", message: "Scan not found" } }, 404]]);
    renderPage(<ScanDetails />, { path: `/scans/${SCAN_B}`, route: "/scans/:scanId" });
    expect(await screen.findByText("Scan not found")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });

  it("makes no request for a malformed id", () => {
    const fetchMock = mockApi([]);
    renderPage(<ScanDetails />, { path: "/scans/not-valid", route: "/scans/:scanId" });
    expect(screen.getByRole("heading", { name: "Not a valid scan ID" })).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("opens finding details without leaving the scan", async () => {
    open();
    const panel = await screen.findByRole("region", { name: "Known vulnerability findings" });
    fireEvent.click(await within(panel).findByRole("button", { name: /Open details/ }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent(`/scans/${SCAN_ID}`);
  });
});
