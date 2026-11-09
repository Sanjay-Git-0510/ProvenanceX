import { screen } from "@testing-library/react";
import CiCd from "../pages/CiCd.jsx";
import { SCAN_ID, expectEveryAllowHasCaveat, mockApi, noRisk, renderPage, riskResult, scanList, scanRow } from "../test/helpers.jsx";

afterEach(() => vi.unstubAllGlobals());

function open(risk, path = `/cicd?scan=${SCAN_ID}`) {
  mockApi([
    [/\/risk$/, risk],
    [/\/scans\?/, scanList([scanRow()])],
  ]);
  return renderPage(<CiCd />, { path, route: "/cicd" });
}

describe("CI/CD", () => {
  it.each([
    ["BLOCK", "Would fail the pipeline"],
    ["REVIEW", /Would pass by default/],
    ["ALLOW", "Would pass the pipeline"],
  ])("maps %s to the gate rule", async (decision, outcome) => {
    open(riskResult({ decision }));
    expect(await screen.findByText(outcome)).toBeInTheDocument();
  });

  it("keeps the ALLOW caveat", async () => {
    const { container } = open(riskResult({ decision: "ALLOW" }));
    await screen.findByText("Would pass the pipeline");
    expectEveryAllowHasCaveat(container);
    expect(container.querySelector(".allow-caveat")).toHaveTextContent(/Not evaluated:.*vulnerability/i);
  });

  it("gives no outcome without a decision and keeps the score null", async () => {
    open(noRisk("not_computed", "scan_failed", "The scan failed"));
    expect(await screen.findByText("No gate outcome: no decision")).toBeInTheDocument();
    expect(screen.getByText("The scan failed")).toBeInTheDocument();
    expect(screen.getByText("ProvenanceX risk").closest(".dl__row")).toHaveTextContent("Not computed yet");
  });

  it("does not trust an unrecognized decision", async () => {
    open(riskResult({ decision: "constructor" }));
    expect(await screen.findByText("No gate outcome: no decision")).toBeInTheDocument();
  });

  it("says plainly that no pipeline runs exist", async () => {
    open(riskResult(), "/cicd");
    expect(await screen.findByText("No pipeline runs recorded")).toBeInTheDocument();
    expect(screen.getByText("Choose a scan to see its decision.")).toBeInTheDocument();
    expect(screen.getByText(/BLOCK fails the pipeline/)).toBeInTheDocument();
  });

  it("labels mock evidence", async () => {
    open(riskResult({ contains_mock_evidence: true }));
    expect(await screen.findByText("Contains mock evidence")).toBeInTheDocument();
  });
});
