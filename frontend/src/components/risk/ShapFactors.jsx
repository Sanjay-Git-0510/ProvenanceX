import { CircleDashed } from "lucide-react";
import { formatFeatureValue, humanize } from "../../lib/format.js";
import { layerLabel } from "../../lib/policyDisplay.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Badge from "../ui/Badge.jsx";
import EvidenceLinkList from "./EvidenceLinkList.jsx";

const DIRECTION = {
  raises_model_probability: "raises",
  lowers_model_probability: "lowers",
};

function Factor({ factor, largest, artifactType }) {
  const width = largest > 0 ? (Math.abs(factor.shap_contribution) / largest) * 100 : 0;
  const direction = DIRECTION[factor.direction] || "unknown";
  return (
    <li className={factor.evaluated ? "factor" : "factor factor--missing"}>
      <div className="factor__head">
        <span className="factor__name">{humanize(sanitizeDisplay(factor.feature))}</span>
        <span className="factor__layer">{layerLabel(factor.layer)}</span>
        {factor.evaluated ? null : (
          <Badge icon={CircleDashed}>Missing evidence: {humanize(sanitizeDisplay(factor.null_reason))}</Badge>
        )}
      </div>
      <div className="factor__bar" aria-hidden="true">
        <span className={`factor__fill factor__fill--${direction}`} style={{ width: `${width}%` }} />
      </div>
      <p className="factor__detail">
        Value: {sanitizeDisplay(formatFeatureValue(factor.value))} · SHAP {factor.shap_contribution.toFixed(3)} ·{" "}
        {direction} the model probability
      </p>
      <EvidenceLinkList links={factor.evidence_links} artifactType={artifactType} />
    </li>
  );
}

/** SHAP explains the ML probability, not the ProvenanceX risk, and says so. */
export default function ShapFactors({ explanation, limit, artifactType }) {
  if (!explanation || explanation.status !== "available") {
    return (
      <p className="state__message">
        {sanitizeDisplay(explanation?.message) || "No SHAP explanation is available for this scan."}
      </p>
    );
  }
  const factors = limit ? explanation.top_factors.slice(0, limit) : explanation.top_factors;
  if (factors.length === 0) return <p className="state__message">The explanation has no factors.</p>;
  const largest = Math.max(...factors.map((factor) => Math.abs(factor.shap_contribution)));
  return (
    <>
      <p className="state__message">
        These factors explain the Random Forest ML probability, not the ProvenanceX risk score.
      </p>
      <ol className="factor-list">
        {factors.map((factor) => (
          <Factor key={factor.feature} factor={factor} largest={largest} artifactType={artifactType} />
        ))}
      </ol>
    </>
  );
}
