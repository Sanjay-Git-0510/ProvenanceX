import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import RiskAnalysis from "../pages/RiskAnalysis.jsx";
import {
  HOST_PATH,
  SCAN_ID,
  calledUrls,
  evidence,
  expectEveryAllowHasCaveat,
  mockApi,
  noRisk,
  renderPage,
  riskResult,
  scanList,
  scanRow,
} from "../test/helpers.jsx";

afterEach(() => vi.unstubAllGlobals());

const LIST = [/\/scans\?limit=100/, scanList([scanRow()])];
const open = (query = `?scan=${SCAN_ID}`) => renderPage(<RiskAnalysis />, { path: `/risk${query}`, route: "/risk" });

function stub(risk = riskResult()) {
  return mockApi([LIST, [/\/risk$/, risk]]);
}

describe("Risk Analysis", () => {
  it("requests nothing from /risk until a scan is chosen", async () => {
    const fetchMock = mockApi([LIST]);
    open("");
    expect(await screen.findByRole("heading", { name: "Choose a scan" })).toBeInTheDocument();
    expect(calledUrls(fetchMock).some((url) => url.endsWith("/risk"))).toBe(false);
  });

  it("gives an ALLOW its caveat", async () => {
    stub();
    const { container } = open();
    const panel = await screen.findByRole("region", { name: "Decision" });
    expect(panel).toHaveTextContent("Not evaluated: Vulnerability, Behavioral");
    expect(panel).toHaveTextContent("Confidence: 0.61 (MEDIUM)");
    expect(panel).toHaveTextContent("crosses 0.60");
    expectEveryAllowHasCaveat(container);
  });

  it("states confidence and the flip for REVIEW as well", async () => {
    stub(riskResult({ decision: "REVIEW", confidence: 0.59, confidence_label: "MEDIUM", allow_reason: null }));
    const { container } = open();
    const panel = await screen.findByRole("region", { name: "Decision" });
    expect(panel).toHaveTextContent("Confidence: 0.59 (MEDIUM)");
    expect(panel).toHaveTextContent("crosses 0.60");
    expect(container.querySelector(".allow-caveat")).toBeNull();
  });

  it("keeps the measures separate and labeled", async () => {
    stub();
    const { container } = open();
    await screen.findByRole("region", { name: "Separate measures" });
    expect(container.querySelector('[data-score="provenancex_risk"]')).toHaveTextContent("ProvenanceX risk");
    expect(container.querySelector('[data-score="cvss_max"]')).toHaveTextContent("CVSS");
    expect(container.querySelector('[data-score="ml_probability"]')).toHaveTextContent("Random Forest");
    expect(container.querySelector('[data-score="anomaly_score"]')).toHaveTextContent("Isolation Forest");
  });

  it("shows nulls as words with each reason, never 0", async () => {
    stub(noRisk("not_computed", "no_rule_layer_scored", "No rule layer could be scored"));
    const { container } = open();
    const panel = await screen.findByRole("region", { name: "Decision" });
    expect(panel).toHaveTextContent("Not computed yet");
    expect(panel).toHaveTextContent("No rule layer could be scored");
    const risk = container.querySelector('[data-score="provenancex_risk"]');
    expect(risk).toHaveTextContent("ProvenanceX risk has no value");
    expect(risk.querySelector(".metric__value")).not.toHaveTextContent(/\d/);
  });

  it("shows a pending scan without a badge for a decision", async () => {
    stub(noRisk("pending", "scan_running", "The scan is running"));
    open();
    const panel = await screen.findByRole("region", { name: "Decision" });
    expect(panel).toHaveTextContent("The scan is running");
    expect(panel).not.toHaveTextContent(/ALLOW|REVIEW|BLOCK/);
  });

  it("shows layer status as text, with evidence links", async () => {
    stub();
    open();
    const panel = await screen.findByRole("region", { name: "Evidence layers" });
    expect(within(panel).getByText("Not evaluated")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Static findings" })).toHaveAttribute(
      "href",
      `/findings?scan=${SCAN_ID}&category=static`,
    );
  });

  it("sends a software scan's graph link to the dependency graph", async () => {
    const links = [{ rel: "graph", href: `/api/v1/scans/${SCAN_ID}/graph` }];
    mockApi([
      LIST,
      [/\/risk$/, riskResult({ evidence_links: links })],
      [/\/evidence/, evidence()],
    ]);
    open();
    expect(await screen.findByRole("link", { name: "Graph" })).toHaveAttribute("href", `/graph?scan=${SCAN_ID}`);
  });

  it("marks missing evidence apart from measured factors", async () => {
    stub();
    const { container } = open();
    await screen.findByRole("region", { name: "ML factors (SHAP)" });
    expect(container.querySelectorAll(".factor--missing")).toHaveLength(1);
    expect(screen.getByRole("region", { name: "Features with no value" })).toHaveTextContent("Network count");
  });

  it("shows the synthetic training notice", async () => {
    stub();
    open();
    expect(await screen.findByText("SYNTHETIC TRAINING DATA")).toBeInTheDocument();
    expect(screen.getByText("Models were trained on synthetic data.")).toBeInTheDocument();
  });

  it("labels mock evidence", async () => {
    stub(riskResult({ contains_mock_evidence: true }));
    open();
    expect(await screen.findByText("CONTAINS MOCK EVIDENCE")).toBeInTheDocument();
  });

  it("shows fired hard rules", async () => {
    stub(
      riskResult({
        decision: "BLOCK",
        allow_reason: null,
        hard_rules: { fired: [{ rule_id: "r", decision: "BLOCK", description: "Known bad", evidence_links: [] }], not_evaluated: [] },
      }),
    );
    open();
    const panel = await screen.findByRole("region", { name: "Hard rules" });
    expect(panel).toHaveTextContent("Known bad");
  });

  it("explains when ML output is unavailable", async () => {
    stub(riskResult({ explanation: { status: "unavailable", message: "ML model unavailable", top_factors: [], not_evaluated_features: [] } }));
    open();
    expect(await screen.findByText("ML model unavailable")).toBeInTheDocument();
  });

  it("redacts artifact-derived text", async () => {
    stub(riskResult({ decision_reasons: [`Found at ${HOST_PATH}`] }));
    const { container } = open();
    await screen.findByText(/Found at \[redacted\]/);
    expect(container).not.toHaveTextContent(HOST_PATH);
  });

  it("uses GET only", async () => {
    const fetchMock = stub();
    open();
    await screen.findByRole("region", { name: "Decision" });
    fetchMock.mock.calls.forEach(([, options]) => expect(options?.method).toBeUndefined());
  });

  it("shows loading and then a retryable error", async () => {
    let fail = true;
    vi.stubGlobal(
      "fetch",
      vi.fn((url) => {
        if (url.includes("limit=100")) return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(scanList([scanRow()])) });
        return Promise.resolve(
          fail
            ? { ok: false, status: 503, json: () => Promise.resolve({ error: { code: "down", message: "Risk down" } }) }
            : { ok: true, status: 200, json: () => Promise.resolve(riskResult()) },
        );
      }),
    );
    open();
    expect(screen.getByText("Loading the risk result")).toBeInTheDocument();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Risk down");
    fail = false;
    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.getByRole("region", { name: "Decision" })).toBeInTheDocument());
  });
});
