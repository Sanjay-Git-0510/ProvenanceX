import { humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import DecisionDisplay from "../risk/DecisionDisplay.jsx";
import RiskScoreValue from "../risk/RiskScoreValue.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import ScanStatusBadge from "./ScanStatusBadge.jsx";

/** The frosted summary. Hashes and tables stay out of it, on solid panels below. */
export default function ScanHero({ evidence, risk, riskNote }) {
  const { artifact, scan_status: scanStatus, mock } = evidence;
  const pending = !risk || risk.status === "pending";
  return (
    <section className="scan-hero glass" aria-label="Scan summary">
      <div className="scan-hero__identity">
        <p className="scan-hero__badges">
          <ScanStatusBadge status={scanStatus} />
          <MockLabel isMock={mock?.contains_mock_evidence}>CONTAINS MOCK EVIDENCE</MockLabel>
        </p>
        <h2 className="scan-hero__name">{sanitizeDisplay(artifact.name)}</h2>
        <p className="scan-hero__meta">
          {humanize(artifact.artifact_type)} from {humanize(artifact.source)}
        </p>
      </div>
      <RiskScoreValue
        value={risk?.risk_score ?? null}
        pending={pending}
        reason={risk?.reason?.message || riskNote}
      />
      <div className="metric">
        <p className="metric__label">Decision</p>
        <DecisionDisplay
          decision={risk?.decision ?? null}
          confidence={risk?.confidence}
          confidenceLabel={risk?.confidence_label}
          notEvaluatedLayers={risk?.not_evaluated_layers}
        />
      </div>
    </section>
  );
}
