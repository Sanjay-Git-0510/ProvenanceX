import { useCallback } from "react";
import { Link } from "react-router-dom";
import useApi from "../../hooks/useApi.js";
import { formatCvss } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import { api } from "../../services/api.js";
import EmptyState from "../EmptyState.jsx";
import DecisionDisplay from "../risk/DecisionDisplay.jsx";
import ErrorState from "../ui/ErrorState.jsx";
import LoadingState from "../ui/LoadingState.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import FindingCategoryBadge, { SeverityBadge } from "./FindingCategoryBadge.jsx";

const SCANS = 3;
const PER_SCAN = 3;

/** Highest-CVSS findings from the latest REVIEW and BLOCK scans. */
export default function AttentionFindings({ scans }) {
  const flagged = scans.filter((scan) => scan.decision === "BLOCK" || scan.decision === "REVIEW").slice(0, SCANS);
  const key = flagged.map((scan) => scan.scan_id).join(",");
  const fetcher = useCallback(
    async ({ signal }) => {
      const ids = key.split(",");
      const pages = await Promise.all(ids.map((id) => api.getFindings(id, { limit: PER_SCAN, signal })));
      return Object.fromEntries(ids.map((id, index) => [id, pages[index]]));
    },
    [key],
  );
  const { status, data, error, reload } = useApi(key ? fetcher : null);

  if (!key) {
    return (
      <EmptyState
        title="No REVIEW or BLOCK scans"
        message="None of the latest 100 scans has a stored REVIEW or BLOCK decision."
        headingLevel={3}
      />
    );
  }
  if (status === "error") return <ErrorState error={error} onRetry={reload} headingLevel={3} />;
  if (!data) return <LoadingState label="Loading findings" lines={2} />;

  return (
    <ul className="attention-list">
      {flagged.map((scan) => {
        const items = data[scan.scan_id]?.items ?? [];
        const total = data[scan.scan_id]?.total ?? 0;
        return (
          <li key={scan.scan_id}>
            <div className="attention-list__head">
              <Link to={`/findings?scan=${scan.scan_id}`}>{sanitizeDisplay(scan.artifact.name)}</Link>
              <DecisionDisplay decision={scan.decision} />
            </div>
            {items.length === 0 ? (
              <p className="state__message">No findings are listed for this scan.</p>
            ) : (
              <ul className="attention-list__findings">
                {items.map((finding) => (
                  <li key={finding.finding_id}>
                    <code>{sanitizeDisplay(finding.identifier)}</code>
                    <FindingCategoryBadge category={finding.category} />
                    <SeverityBadge severity={finding.severity} />
                    <span className="attention-list__cvss">CVSS {formatCvss(finding.cvss?.score)}</span>
                    <MockLabel source={finding.source} isMock={finding.is_mock} />
                  </li>
                ))}
              </ul>
            )}
            {total > items.length ? (
              <p className="state__message">
                Showing {items.length} of {total}.
              </p>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
