import { formatRiskScore } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";

/** The ProvenanceX risk score. Null is words, never 0, and no band is derived from it. */
export default function RiskScoreValue({ value, pending = false, reason }) {
  const isNumber = typeof value === "number" && Number.isFinite(value);
  return (
    <div className="metric">
      <p className="metric__label">ProvenanceX risk (0 to 1)</p>
      <p className={isNumber ? "metric__value" : "metric__value metric__value--missing"}>
        {isNumber || !pending ? formatRiskScore(value) : "Pending"}
      </p>
      {!isNumber && reason ? <p className="metric__note">{sanitizeDisplay(reason)}</p> : null}
    </div>
  );
}
