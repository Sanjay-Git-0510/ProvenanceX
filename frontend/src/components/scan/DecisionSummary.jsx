import { CircleDashed } from "lucide-react";
import { formatConfidence, formatCount, NOT_COMPUTED } from "../../lib/format.js";
import AllowCaveat from "../risk/AllowCaveat.jsx";
import Badge from "../ui/Badge.jsx";

const ROWS = [
  { key: "ALLOW", tone: "allow" },
  { key: "REVIEW", tone: "review" },
  { key: "BLOCK", tone: "block" },
  { key: null, label: NOT_COMPUTED, icon: CircleDashed, tone: "neutral" },
];

function confidenceRange(scans) {
  const values = scans.map((scan) => scan.confidence).filter((value) => typeof value === "number");
  if (values.length === 0) return NOT_COMPUTED;
  const low = formatConfidence(Math.min(...values));
  const high = formatConfidence(Math.max(...values));
  return low === high ? low : `${low} to ${high}`;
}

function Row({ row, count, total, children }) {
  const width = total > 0 ? (count / total) * 100 : 0;
  return (
    <li className="summary-row" data-allow={row.key === "ALLOW" ? "true" : undefined}>
      <div className="summary-row__head">
        <Badge tone={row.tone} icon={row.icon}>
          {row.key || row.label}
        </Badge>
        <span className="summary-row__count">{formatCount(count)}</span>
      </div>
      <div className="summary-row__bar" aria-hidden="true">
        <span className={`summary-row__fill summary-row__fill--${row.tone}`} style={{ width: `${width}%` }} />
      </div>
      {children}
    </li>
  );
}

/** Decisions among the scans passed in. It counts stored decisions and infers nothing. */
export default function DecisionSummary({ scans }) {
  const allowed = scans.filter((scan) => scan.decision === "ALLOW");
  return (
    <ul className="summary-list">
      {ROWS.map((row) => {
        const count = scans.filter((scan) => (scan.decision ?? null) === row.key).length;
        return (
          <Row key={row.key ?? "none"} row={row} count={count} total={scans.length}>
            {row.key === "ALLOW" ? (
              <AllowCaveat confidenceText={confidenceRange(allowed)} layersNote="listed on each scan" />
            ) : null}
          </Row>
        );
      })}
    </ul>
  );
}
