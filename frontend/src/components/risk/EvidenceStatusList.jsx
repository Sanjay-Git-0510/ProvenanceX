import { KIND_LABELS, evidenceMeta } from "../../lib/evidenceStatus.js";
import { humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Badge from "../ui/Badge.jsx";

/**
 * What kind of evidence the result rests on. Confirmed evidence is grouped and labelled apart
 * from signals (known vulnerabilities) and gaps (weak, unverified or missing evidence).
 */
export default function EvidenceStatusList({ items, legacy = false }) {
  if (!Array.isArray(items) || !items.length) {
    return (
      <p className="state__message">
        {legacy
          ? "Evidence status was not recorded: this result was stored by an earlier policy."
          : "No evidence states apply: nothing confirmed, no known vulnerabilities and no recorded gaps."}
      </p>
    );
  }
  const groups = ["confirmed", "signal", "gap"].map((kind) => ({
    kind,
    entries: items.filter((item) => evidenceMeta(item.state).kind === kind),
  }));
  return (
    <div className="evidence-status">
      {groups
        .filter((group) => group.entries.length)
        .map((group) => (
          <section key={group.kind} className={`evidence-status__group evidence-status__group--${group.kind}`}>
            <h3>{KIND_LABELS[group.kind]}</h3>
            <ul className="evidence-status__list">
              {group.entries.map((item) => {
                const meta = evidenceMeta(item.state);
                return (
                  <li key={item.state} className="evidence-status__item">
                    <Badge tone={meta.tone} icon={meta.icon}>
                      {meta.label}
                    </Badge>
                    <span className="evidence-status__confirmed">
                      {item.confirmed ? "Confirmed" : "Not confirmed"}
                    </span>
                    {item.note ? <p className="evidence-status__note">{sanitizeDisplay(item.note)}</p> : null}
                    {item.items?.length ? (
                      <p className="evidence-status__items">
                        {item.items.map((name) => humanize(sanitizeDisplay(name))).join(", ")}
                      </p>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
    </div>
  );
}
