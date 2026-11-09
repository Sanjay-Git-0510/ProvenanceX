import { formatDateTime, humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import EmptyState from "../EmptyState.jsx";
import Badge from "../ui/Badge.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import Panel from "../ui/Panel.jsx";

const STAGE_TONES = { completed: "neutral", partial: "review", unavailable: "unknown", skipped: "unknown", error: "block" };

function Notes({ items }) {
  return items?.length ? (
    <ul className="timeline__notes">
      {items.map((item, index) => (
        <li key={index}>{sanitizeDisplay(item)}</li>
      ))}
    </ul>
  ) : null;
}

// The API lists stages by name. Stages with no time go last, in their original order.
function byTime(stages) {
  const time = (stage) => {
    const parsed = Date.parse(stage.started_at || stage.finished_at);
    return Number.isNaN(parsed) ? Number.MAX_SAFE_INTEGER : parsed;
  };
  return [...stages].sort((a, b) => time(a) - time(b));
}

/** The pipeline stages as they ran. Doubles as scan progress while a scan is running. */
export default function Timeline({ stages, className }) {
  return (
    <Panel title="Timeline" className={className}>
      {stages.length === 0 ? (
        <EmptyState title="No stages yet" message="No pipeline stage has reported yet." headingLevel={3} />
      ) : (
        <ol className="timeline">
          {byTime(stages).map((stage) => (
            <li key={stage.name} className="timeline__item">
              <div className="timeline__head">
                <h3>{humanize(sanitizeDisplay(stage.name))}</h3>
                <Badge tone={STAGE_TONES[stage.status] || "unknown"}>
                  {stage.status ? humanize(stage.status) : "No status"}
                </Badge>
                <MockLabel source={stage.source} isMock={stage.is_mock} />
              </div>
              <p className="timeline__time">{formatDateTime(stage.finished_at || stage.started_at)}</p>
              {stage.reason ? <p className="state__message">{sanitizeDisplay(stage.reason)}</p> : null}
              {stage.error_message ? <p className="state__message">{sanitizeDisplay(stage.error_message)}</p> : null}
              <Notes items={stage.incomplete_reasons} />
              <Notes items={stage.limitations} />
              <Notes items={stage.warnings} />
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}
