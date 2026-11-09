import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import DecisionDisplay from "../components/risk/DecisionDisplay.jsx";
import EvidenceLinkList from "../components/risk/EvidenceLinkList.jsx";
import HardRules from "../components/risk/HardRules.jsx";
import RiskScoreValue from "../components/risk/RiskScoreValue.jsx";
import SeparateScores from "../components/risk/SeparateScores.jsx";
import ShapFactors from "../components/risk/ShapFactors.jsx";
import TrainingNotice from "../components/risk/TrainingNotice.jsx";
import DecisionBadge from "../components/ui/DecisionBadge.jsx";
import { HOST_PATH, SCAN_ID, expectEveryAllowHasCaveat, noRisk, riskResult } from "../test/helpers.jsx";

const future = { v7_startTransition: true, v7_relativeSplatPath: true };
const withRouter = (element) => render(<MemoryRouter future={future}>{element}</MemoryRouter>);

function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return ["__tests__", "test"].includes(entry.name) ? [] : sourceFiles(path);
    return /\.jsx?$/.test(entry.name) ? [path] : [];
  });
}

describe("ALLOW always carries its caveat", () => {
  it("the guard fails on a bare ALLOW badge", () => {
    const { container } = render(<DecisionBadge decision="ALLOW" />);
    expect(() => expectEveryAllowHasCaveat(container)).toThrow(/caveat container/);
  });

  it("the guard fails when nothing is rendered", () => {
    const { container } = render(<div />);
    expect(() => expectEveryAllowHasCaveat(container)).toThrow();
  });

  it("only DecisionDisplay may render a decision badge", () => {
    const importers = sourceFiles(resolve(process.cwd(), "src"))
      .filter((path) => /import DecisionBadge/.test(readFileSync(path, "utf8")))
      .map((path) => path.split("/").pop());
    expect(importers).toEqual(["DecisionDisplay.jsx"]);
  });

  it("nothing paints an ALLOW badge by hand except the labeled summary", () => {
    const painters = sourceFiles(resolve(process.cwd(), "src"))
      .filter((path) => /\bALLOW\b/.test(readFileSync(path, "utf8")))
      .map((path) => path.split("/").pop())
      .sort();
    expect(painters).toEqual([
      "AllowCaveat.jsx",
      "CiCd.jsx",
      "DecisionBadge.jsx",
      "DecisionDisplay.jsx",
      "DecisionSummary.jsx",
      "RecentScansTable.jsx",
      "RiskAnalysis.jsx",
    ]);
  });

  it("shows confidence, layers and the flip threshold", () => {
    const { container } = render(
      <DecisionDisplay decision="ALLOW" confidence={0.61} confidenceLabel="MEDIUM" notEvaluatedLayers={["vulnerability", "ai_specific"]} />,
    );
    expectEveryAllowHasCaveat(container);
    expect(container).toHaveTextContent("Confidence: 0.61 (MEDIUM)");
    expect(container).toHaveTextContent("Not evaluated: Vulnerability, AI-specific");
    expect(container).toHaveTextContent("crosses 0.60");
  });

  it("says none when every layer was evaluated", () => {
    const { container } = render(<DecisionDisplay decision="ALLOW" confidence={0.9} notEvaluatedLayers={[]} />);
    expect(container).toHaveTextContent("Not evaluated: none");
  });

  it("stays explicit when the layers are missing", () => {
    const { container } = render(<DecisionDisplay decision="ALLOW" confidence={null} />);
    expectEveryAllowHasCaveat(container);
    expect(container).toHaveTextContent("Not evaluated: could not be loaded");
    expect(container).toHaveTextContent("Confidence: Not computed yet");
  });

  it("adds no caveat to REVIEW or a null decision", () => {
    const { container, rerender } = render(<DecisionDisplay decision="REVIEW" />);
    expect(container.querySelector(".allow-caveat")).toBeNull();
    rerender(<DecisionDisplay decision={null} />);
    expect(container).toHaveTextContent("Not computed yet");
  });
});

describe("RiskScoreValue", () => {
  it("shows null as not computed, with its reason, never 0", () => {
    const { container } = render(<RiskScoreValue value={null} reason="No layer could be scored" />);
    expect(container).toHaveTextContent("Not computed yet");
    expect(container).toHaveTextContent("No layer could be scored");
    expect(container.querySelector(".metric__value")).not.toHaveTextContent(/\d/);
  });

  it("keeps a real 0", () => {
    render(<RiskScoreValue value={0} />);
    expect(screen.getByText("0.000")).toBeInTheDocument();
  });

  it("shows pending", () => {
    render(<RiskScoreValue value={null} pending />);
    expect(screen.getByText("Pending")).toBeInTheDocument();
  });
});

describe("SeparateScores", () => {
  it("keeps the four values separately labeled", () => {
    const { container } = render(<SeparateScores scores={riskResult().scores} />);
    expect(container.querySelector('[data-score="provenancex_risk"]')).toHaveTextContent("0.300");
    expect(container.querySelector('[data-score="cvss_max"]')).toHaveTextContent("7.5");
    expect(container.querySelector('[data-score="ml_probability"]')).toHaveTextContent("0.465");
    expect(container.querySelector('[data-score="anomaly_score"]')).toHaveTextContent("0.510");
  });

  it("gives each null value its own reason and no number", () => {
    const { container } = render(<SeparateScores scores={noRisk("not_computed", "x", "y").scores} />);
    expect(container.querySelector('[data-score="provenancex_risk"]')).toHaveTextContent("Not computed yet");
    expect(container.querySelector('[data-score="cvss_max"]')).toHaveTextContent("No CVSS score");
    expect(container.querySelector('[data-score="ml_probability"]')).toHaveTextContent("ML probability has no value");
    expect(container.querySelector(".metric__value")).not.toHaveTextContent(/\d/);
  });
});

describe("ShapFactors", () => {
  const { explanation } = riskResult();

  it("marks missing evidence differently from measured factors", () => {
    const { container } = withRouter(<ShapFactors explanation={explanation} />);
    const missing = container.querySelectorAll(".factor--missing");
    expect(missing).toHaveLength(1);
    expect(missing[0]).toHaveTextContent("Missing evidence: Not determinable");
    expect(missing[0]).toHaveTextContent("Value: No value");
  });

  it("says what SHAP explains and the direction in words", () => {
    const { container } = withRouter(<ShapFactors explanation={explanation} />);
    expect(container).toHaveTextContent("not the ProvenanceX risk score");
    expect(container).toHaveTextContent("raises the model probability");
    expect(container).toHaveTextContent("lowers the model probability");
  });

  it("explains an unavailable result", () => {
    withRouter(<ShapFactors explanation={{ status: "unavailable", message: "ML model unavailable" }} />);
    expect(screen.getByText("ML model unavailable")).toBeInTheDocument();
  });

  it("honours the limit", () => {
    const { container } = withRouter(<ShapFactors explanation={explanation} limit={1} />);
    expect(container.querySelectorAll(".factor-list > li")).toHaveLength(1);
  });
});

describe("other risk parts", () => {
  it("TrainingNotice labels synthetic data and mock evidence", () => {
    const { container } = render(<TrainingNotice trainingData={riskResult().training_data} containsMock />);
    expect(container).toHaveTextContent("SYNTHETIC TRAINING DATA");
    expect(container).toHaveTextContent("CONTAINS MOCK EVIDENCE");
  });

  it("HardRules shows fired rules, and rules it could not evaluate", () => {
    const { container } = withRouter(
      <HardRules
        hardRules={{
          fired: [{ rule_id: "r1", decision: "BLOCK", description: `Hit ${HOST_PATH}`, evidence_links: [] }],
          not_evaluated: ["hash_mismatch"],
        }}
      />,
    );
    expect(container).toHaveTextContent("Fired: BLOCK");
    expect(container).toHaveTextContent("Hash mismatch");
    expect(container).not.toHaveTextContent(HOST_PATH);
  });

  it("EvidenceLinkList drops unrecognized links", () => {
    withRouter(
      <EvidenceLinkList
        links={[
          { rel: "static_findings", href: `/api/v1/scans/${SCAN_ID}/findings?category=static` },
          { rel: "evil", href: "javascript:alert(1)" },
        ]}
      />,
    );
    expect(screen.getAllByRole("link")).toHaveLength(1);
    expect(screen.getByRole("link", { name: "Static findings" })).toHaveAttribute(
      "href",
      `/findings?scan=${SCAN_ID}&category=static`,
    );
  });
});
