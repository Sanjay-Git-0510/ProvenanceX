import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import Dashboard from "../pages/Dashboard.jsx";
import {
  SCAN_B,
  SCAN_ID,
  calledUrls,
  expectEveryAllowHasCaveat,
  finding,
  findingsPage,
  mockApi,
  renderPage,
  riskResult,
  scanList,
  scanRow,
} from "../test/helpers.jsx";

const ALLOW_ROW = scanRow({ decision: "ALLOW", risk_score: 0.3, confidence: 0.61 });
const NULL_ROW = scanRow({ scan_id: SCAN_B, artifact: { name: "old-scan", artifact_type: "model", source: "upload" } });

function stubDashboard(items, extra = []) {
  return mockApi([
    [/\/risk$/, riskResult()],
    [/\/findings/, findingsPage([finding()])],
    ...extra,
    [/\/scans\?/, scanList(items)],
  ]);
}

afterEach(() => vi.unstubAllGlobals());

const recentPanel = () => screen.getByRole("region", { name: "Recent scans" });

describe("Dashboard", () => {
  it("lists scans from GET /scans", async () => {
    const fetchMock = stubDashboard([ALLOW_ROW]);
    renderPage(<Dashboard />);
    expect(await within(recentPanel()).findByRole("link", { name: "demo-app" })).toHaveAttribute("href", `/scans/${SCAN_ID}`);
    expect(calledUrls(fetchMock)).toContain("/api/v1/scans?limit=20&offset=0");
  });

  it("shows a null decision and score as not computed yet, never 0", async () => {
    stubDashboard([NULL_ROW]);
    renderPage(<Dashboard />);
    const row = (await within(recentPanel()).findByRole("link", { name: "old-scan" })).closest("tr");
    expect(within(row).getAllByText("Not computed yet")).toHaveLength(2);
    expect(row.querySelector(".is-end")).not.toHaveTextContent(/\d/);
  });

  it("keeps a real 0 score", async () => {
    stubDashboard([scanRow({ decision: "REVIEW", risk_score: 0, confidence: 0.4 })]);
    renderPage(<Dashboard />);
    expect(await within(recentPanel()).findByText("0.000")).toBeInTheDocument();
  });

  it("renders every ALLOW with its not-evaluated layers and confidence", async () => {
    stubDashboard([ALLOW_ROW]);
    const { container } = renderPage(<Dashboard />);
    const row = (await within(recentPanel()).findByRole("link", { name: "demo-app" })).closest("tr");
    await waitFor(() => expect(row).toHaveTextContent("Not evaluated: Vulnerability, Behavioral"));
    expect(row).toHaveTextContent("Confidence: 0.61 (MEDIUM)");
    expectEveryAllowHasCaveat(container, { minimum: 2 });
  });

  it("calls /risk only for ALLOW rows, so listing computes nothing", async () => {
    const fetchMock = stubDashboard([ALLOW_ROW, NULL_ROW]);
    renderPage(<Dashboard />);
    await within(recentPanel()).findByRole("link", { name: "old-scan" });
    await waitFor(() => expect(calledUrls(fetchMock)).toContain(`/api/v1/scans/${SCAN_ID}/risk`));
    expect(calledUrls(fetchMock)).not.toContain(`/api/v1/scans/${SCAN_B}/risk`);
  });

  it("makes no write requests", async () => {
    const fetchMock = stubDashboard([ALLOW_ROW]);
    renderPage(<Dashboard />);
    await within(recentPanel()).findByRole("link", { name: "demo-app" });
    fetchMock.mock.calls.forEach(([, options]) => expect(options?.method).toBeUndefined());
  });

  it("states when an ALLOW row's layers could not be loaded", async () => {
    mockApi([
      [/\/risk$/, { error: { code: "down", message: "x" } }, 503],
      [/\/scans\?/, scanList([ALLOW_ROW])],
    ]);
    const { container } = renderPage(<Dashboard />);
    const row = (await within(recentPanel()).findByRole("link", { name: "demo-app" })).closest("tr");
    await waitFor(() => expect(row).toHaveTextContent("Not evaluated: could not be loaded"));
    expectEveryAllowHasCaveat(container);
  });

  it("shows true status totals from filtered lists", async () => {
    stubDashboard([], [[/status=failed/, scanList([], { total: 4 })]]);
    renderPage(<Dashboard />);
    const value = await screen.findByText("4");
    expect(value.parentElement).toHaveTextContent("Failed");
  });

  it("counts decisions and says how many scans it covered", async () => {
    stubDashboard([ALLOW_ROW, NULL_ROW]);
    const { container } = renderPage(<Dashboard />);
    await screen.findByText("Latest 2 scans");
    const rows = container.querySelectorAll(".summary-row");
    expect(rows[0]).toHaveTextContent("ALLOW1");
    expect(rows[3]).toHaveTextContent("Not computed yet1");
    expect(rows[0]).toHaveTextContent("Confidence: 0.61");
    expect(rows[0]).toHaveTextContent("Not evaluated: listed on each scan");
  });

  it("lists findings for REVIEW and BLOCK scans only", async () => {
    const fetchMock = stubDashboard([
      scanRow({ decision: "BLOCK", risk_score: 0.9, confidence: 0.8 }),
      scanRow({ scan_id: SCAN_B, decision: "ALLOW", risk_score: 0.1, confidence: 0.7 }),
    ]);
    renderPage(<Dashboard />);
    expect(await screen.findByText("GHSA-aaaa-bbbb-cccc")).toBeInTheDocument();
    expect(calledUrls(fetchMock)).toContain(`/api/v1/scans/${SCAN_ID}/findings?limit=3`);
    expect(calledUrls(fetchMock)).not.toContain(`/api/v1/scans/${SCAN_B}/findings?limit=3`);
  });

  it("shows an empty state", async () => {
    stubDashboard([]);
    renderPage(<Dashboard />);
    expect(await screen.findByRole("heading", { name: "No scans yet" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "No REVIEW or BLOCK scans" })).toBeInTheDocument();
  });

  it("shows loading", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    renderPage(<Dashboard />);
    expect(screen.getByText("Loading scans")).toBeInTheDocument();
  });

  it("shows an error and retries", async () => {
    let fail = true;
    const handler = () => (fail ? { error: { code: "down", message: "API down" } } : scanList([]));
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve({ ok: !fail, status: fail ? 503 : 200, json: () => Promise.resolve(handler()) }),
      ),
    );
    renderPage(<Dashboard />);
    const panel = recentPanel();
    await within(panel).findByText("API down");
    fail = false;
    fireEvent.click(within(panel).getByRole("button", { name: "Retry" }));
    expect(await within(panel).findByRole("heading", { name: "No scans yet" })).toBeInTheDocument();
  });

  it("pages through scans", async () => {
    const fetchMock = mockApi([
      [/limit=20&offset=20/, scanList([scanRow({ artifact: { name: "page-two", artifact_type: "software", source: "upload" } })], { total: 21, offset: 20 })],
      [/\/scans\?/, scanList([NULL_ROW], { total: 21, has_more: true })],
    ]);
    renderPage(<Dashboard />);
    const panel = recentPanel();
    fireEvent.click(await within(panel).findByRole("button", { name: "Next" }));
    expect(await within(panel).findByRole("link", { name: "page-two" })).toBeInTheDocument();
    expect(calledUrls(fetchMock)).toContain("/api/v1/scans?limit=20&offset=20");
  });

  it("redacts a host path in an artifact name", async () => {
    stubDashboard([scanRow({ artifact: { name: "/home/victim/app", artifact_type: "software", source: "upload" } })]);
    const { container } = renderPage(<Dashboard />);
    await within(recentPanel()).findByRole("link", { name: "[redacted]" });
    expect(container).not.toHaveTextContent("/home/victim");
  });
});
