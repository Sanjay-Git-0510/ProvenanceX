import { formatConfidence, formatCount, NOT_COMPUTED } from "../../lib/format.js";
import AllowCaveat from "../risk/AllowCaveat.jsx";
import Badge from "../ui/Badge.jsx";

const ROWS = [
  { key: "ALLOW", tone: "allow" },
  { key: "REVIEW", tone: "review" },
  { key: "BLOCK", tone: "block" },
];

function confidenceRange(scans) {
  const values = scans.map((scan) => scan.confidence).filter((value) => typeof value === "number");
  if (values.length === 0) return NOT_COMPUTED;
  const low = formatConfidence(Math.min(...values));
  const high = formatConfidence(Math.max(...values));
  return low === high ? low : `${low} to ${high}`;
}

function Row({ row, count, total }) {
  const width = total > 0 ? (count / total) * 100 : 0;
  return (
    <li className="summary-row">
      <div className="summary-row__head">
        <Badge tone={row.tone} icon={row.icon}>
          {row.key || row.label}
        </Badge>
        <span className="summary-row__count">{formatCount(count)}</span>
      </div>
      <div className="summary-row__bar" aria-hidden="true">
        <span className={`summary-row__fill summary-row__fill--${row.tone}`} style={{ width: `${width}%` }} />
      </div>
    </li>
  );
}

/** Decisions among the scans passed in. It counts stored decisions and infers nothing. */
export default function DecisionSummary({ scans }) {
  const total = scans.filter((scan) => ROWS.some((row) => row.key === scan.decision)).length;
  const allowed = scans.filter((scan) => scan.decision === "ALLOW");
  // The bars stay together; the ALLOW caveat sits below them. data-allow marks the whole card as
  // the ALLOW badge's caveat container, so the caveat can never be dropped from it.
  return (
    <div className="decision-summary" data-allow="true">
      <ul className="summary-list">
        {ROWS.map((row) => (
          <Row
            key={row.key}
            row={row}
            count={scans.filter((scan) => scan.decision === row.key).length}
            total={total}
          />
        ))}
      </ul>
      <div className="decision-summary__note">
        <p className="decision-summary__note-title">About the ALLOW decisions above</p>
        <AllowCaveat confidenceText={confidenceRange(allowed)} layersNote="listed on each scan" />
      </div>
    </div>
  );
}
