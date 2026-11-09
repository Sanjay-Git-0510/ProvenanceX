import { formatCount, humanize } from "../../lib/format.js";
import { categoryLabel, CATEGORY_NAMES } from "../findings/FindingCategoryBadge.jsx";
import Panel from "../ui/Panel.jsx";

/** Counts cover all rows, including those outside the requested page. */
export default function EvidenceSummary({ evidence, className }) {
  const { findings, components, stages } = evidence;
  const incomplete = stages.filter((stage) => stage.status !== "completed");
  return (
    <Panel title="Evidence summary" className={className}>
      <dl className="dl">
        {CATEGORY_NAMES.map((name) => (
          <div className="dl__row" key={name}>
            <dt>{categoryLabel(name)}</dt>
            <dd>{formatCount(findings.by_category[name] ?? 0)}</dd>
          </div>
        ))}
        <div className="dl__row">
          <dt>Components</dt>
          <dd>{formatCount(components.page.total)}</dd>
        </div>
        <div className="dl__row">
          <dt>Stages not completed</dt>
          <dd>{incomplete.length ? incomplete.map((stage) => humanize(stage.name)).join(", ") : "None"}</dd>
        </div>
      </dl>
    </Panel>
  );
}
