import { humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Badge from "../ui/Badge.jsx";
import EvidenceLinkList from "./EvidenceLinkList.jsx";

export default function HardRules({ hardRules, artifactType }) {
  const fired = hardRules?.fired || [];
  const notEvaluated = hardRules?.not_evaluated || [];
  return (
    <>
      {fired.length === 0 ? (
        <p className="state__message">No hard rule fired among the rules that could be evaluated.</p>
      ) : (
        <ul className="rule-list">
          {fired.map((rule) => (
            <li key={rule.rule_id}>
              <Badge tone="block">Fired: {sanitizeDisplay(rule.decision)}</Badge>
              <p>{sanitizeDisplay(rule.description)}</p>
              <EvidenceLinkList links={rule.evidence_links} artifactType={artifactType} />
            </li>
          ))}
        </ul>
      )}
      {notEvaluated.length > 0 ? (
        <p className="state__message">
          <strong>Rules not evaluated:</strong> {notEvaluated.map((rule) => humanize(sanitizeDisplay(rule))).join(", ")}
        </p>
      ) : null}
    </>
  );
}
