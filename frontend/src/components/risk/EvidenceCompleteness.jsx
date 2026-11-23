import { CircleCheck, CircleDashed, CircleMinus, CircleSlash } from "lucide-react";
import { formatConfidence, humanize } from "../../lib/format.js";
import { layerLabel } from "../../lib/policyDisplay.js";

const ROWS = [
  { key: "evaluated_layers", label: "Evaluated", icon: CircleCheck },
  { key: "partial_layers", label: "Partial", icon: CircleMinus },
  { key: "not_evaluated_layers", label: "Not evaluated (missing, not clean)", icon: CircleDashed },
  { key: "not_applicable_layers", label: "Not applicable", icon: CircleSlash },
];

/** Which rule layers had evidence. Not evaluated is missing evidence, never a clean result. */
export default function EvidenceCompleteness({ completeness }) {
  if (!completeness) return <p className="state__message">Evidence completeness was not recorded.</p>;
  return (
    <div className="completeness">
      <p className="state__message">
        Confidence {formatConfidence(completeness.confidence)}
        {completeness.confidence_label ? ` (${humanize(completeness.confidence_label)})` : ""}
      </p>
      <dl className="completeness__list">
        {ROWS.map(({ key, label, icon: Icon }) => {
          const layers = completeness[key] || [];
          return (
            <div key={key} className="completeness__row">
              <dt>
                <Icon size={14} aria-hidden="true" /> {label} ({layers.length})
              </dt>
              <dd>{layers.length ? layers.map(layerLabel).join(", ") : "None"}</dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}
