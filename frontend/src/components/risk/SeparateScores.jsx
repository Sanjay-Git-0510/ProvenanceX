import { formatCvss, formatProbability, formatRiskScore } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";

const MEASURES = [
  ["provenancex_risk", formatRiskScore],
  ["cvss_max", formatCvss],
  ["ml_probability", formatProbability],
  ["anomaly_score", formatProbability],
];

/** Four separately labeled measures. They are never merged or converted into each other. */
export default function SeparateScores({ scores }) {
  return (
    <ul className="score-list">
      {MEASURES.map(([key, format]) => {
        const score = scores?.[key];
        return (
          <li key={key} className="metric" data-score={key}>
            <p className="metric__label">{sanitizeDisplay(score?.label) || key}</p>
            <p className={score?.value == null ? "metric__value metric__value--missing" : "metric__value"}>
              {format(score?.value)}
            </p>
            {score?.value == null && score?.reason ? (
              <p className="metric__note">{sanitizeDisplay(score.reason)}</p>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
