import { CircleCheck, CircleDashed, Info, ShieldAlert } from "lucide-react";
import { formatConfidence, formatRiskScore, humanize } from "../../lib/format.js";
import { BLOCK_DOWNGRADE_NOTICE } from "../../lib/policyDisplay.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import DecisionDisplay from "./DecisionDisplay.jsx";
import RiskLevelBadge from "./RiskLevelBadge.jsx";

function confirmedText(confirmed) {
  if (confirmed === true) return { icon: ShieldAlert, text: "Rests on confirmed evidence (tampering or dangerous behaviour)." };
  if (confirmed === false) return { icon: CircleDashed, text: "No confirmed evidence: the result rests on signals and gaps only." };
  return { icon: Info, text: "Evidence status was not recorded for this result." };
}

/**
 * The /risk `summary`: score and band, decision, confidence, reasons, critical findings and the
 * policy notes. showDecision=false when the page already renders the decision beside it. Results with no summary (no decision stored) say so instead of hiding the panel.
 */
export default function RiskSummaryPanel({ summary, notEvaluatedLayers, showDecision = true }) {
  if (!summary) {
    return (
      <p className="state__message">
        No risk summary is available for this result. It may predate policy v2, or no decision was stored.
      </p>
    );
  }
  const confirmed = confirmedText(summary.confirmed_evidence);
  const ConfirmedIcon = confirmed.icon;
  return (
    <div className="risk-summary">
      <div className="risk-summary__metrics">
        <div className="metric">
          <p className="metric__label">ProvenanceX risk (0 to 1)</p>
          <p className={typeof summary.risk_score === "number" ? "metric__value" : "metric__value metric__value--missing"}>
            {formatRiskScore(summary.risk_score)}
          </p>
          <p className="risk-summary__level">
            <RiskLevelBadge level={summary.risk_level} />
          </p>
        </div>
        {showDecision ? (
          <div className="metric">
            <p className="metric__label">Decision</p>
            <DecisionDisplay
              decision={summary.decision}
              confidence={summary.confidence}
              confidenceLabel={summary.evidence_completeness?.confidence_label}
              notEvaluatedLayers={notEvaluatedLayers ?? summary.evidence_completeness?.not_evaluated_layers}
            />
          </div>
        ) : null}
        <div className="metric">
          <p className="metric__label">Confidence</p>
          <p className="metric__value">{formatConfidence(summary.confidence)}</p>
          {summary.evidence_completeness?.confidence_label ? (
            <p className="metric__note">{humanize(summary.evidence_completeness.confidence_label)}</p>
          ) : null}
        </div>
      </div>
      <p className="notice panel__section">
        <ConfirmedIcon size={16} aria-hidden="true" />
        <span>{confirmed.text}</span>
      </p>
      {summary.decision_basis ? (
        <p className="state__message panel__section">
          <strong>Basis:</strong> {humanize(sanitizeDisplay(summary.decision_basis))}
        </p>
      ) : null}
      {summary.decision_reasons?.length ? (
        <ul className="reason-list panel__section" aria-label="Decision reasons">
          {summary.decision_reasons.map((reason, index) => (
            <li key={index}>{sanitizeDisplay(reason)}</li>
          ))}
        </ul>
      ) : null}
      <div className="panel__section">
        <h3>Critical findings</h3>
        {summary.critical_findings?.length ? (
          <ul className="rule-list">
            {summary.critical_findings.map((finding) => (
              <li key={finding.rule_id}>
                <strong>{sanitizeDisplay(finding.rule_id)}</strong> ({sanitizeDisplay(finding.decision)}):{" "}
                {sanitizeDisplay(finding.description)}
              </li>
            ))}
          </ul>
        ) : (
          <p className="state__message">
            <CircleCheck size={14} aria-hidden="true" /> No hard rule fired.
          </p>
        )}
        {summary.hard_rules_not_evaluated?.length ? (
          <p className="metric__note">
            Hard rules not evaluated (missing evidence, not a pass):{" "}
            {summary.hard_rules_not_evaluated.map((rule) => sanitizeDisplay(rule)).join(", ")}
          </p>
        ) : null}
      </div>
      <div className="notice panel__section">
        <Info size={16} aria-hidden="true" />
        <div>
          {(summary.notes || []).map((note, index) => (
            <p key={index}>{sanitizeDisplay(note)}</p>
          ))}
          <p>{BLOCK_DOWNGRADE_NOTICE}</p>
          <p>Policy: {sanitizeDisplay(summary.policy_version)}</p>
        </div>
      </div>
    </div>
  );
}
