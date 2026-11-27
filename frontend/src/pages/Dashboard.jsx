import { useCallback, useState } from "react";
import EmptyState from "../components/EmptyState.jsx";
import AttentionFindings from "../components/findings/AttentionFindings.jsx";
import DecisionSummary from "../components/scan/DecisionSummary.jsx";
import RecentScansTable from "../components/scan/RecentScansTable.jsx";
import ScanCounts from "../components/scan/ScanCounts.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import LoadingState from "../components/ui/LoadingState.jsx";
import Pagination from "../components/ui/Pagination.jsx";
import Panel from "../components/ui/Panel.jsx";
import useApi from "../hooks/useApi.js";
import { isUncomputedCompleted } from "../lib/format.js";
import { POLL_MS } from "../lib/polling.js";
import { api } from "../services/api.js";

const PAGE_SIZE = 20;
const SUMMARY_SIZE = 100;

function RecentScans() {
  const [offset, setOffset] = useState(0);
  const fetcher = useCallback(
    (options) => api.listScans({ limit: PAGE_SIZE, offset, ...options }),
    [offset],
  );
  const { status, data, error, reload } = useApi(fetcher, { pollMs: POLL_MS });

  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load scans" headingLevel={3} />;
  if (!data) return <LoadingState label="Loading scans" />;
  const page = data.page ?? { total: 0, limit: PAGE_SIZE, offset, has_more: false };
  return (
    <>
      <RecentScansTable
        scans={(data.items ?? []).filter((scan) => !isUncomputedCompleted(scan))}
        empty={
          <EmptyState
            title="No scans yet"
            message="No scans recorded yet. Click 'Start scan' to analyze an artifact."
            headingLevel={3}
          />
        }
      />
      <Pagination
        label="Recent scans pages"
        total={page.total}
        limit={page.limit}
        offset={page.offset}
        hasMore={page.has_more}
        onChange={setOffset}
      />
    </>
  );
}

function LatestScanPanels() {
  const fetcher = useCallback((options) => api.listScans({ limit: SUMMARY_SIZE, ...options }), []);
  const { status, data, error, reload } = useApi(fetcher, { pollMs: POLL_MS });
  const all = data?.items ?? [];
  const items = all.filter((scan) => !isUncomputedCompleted(scan));
  const body = (content) => {
    if (status === "error") return <ErrorState error={error} onRetry={reload} headingLevel={3} />;
    if (!data) return <LoadingState label="Loading" lines={2} />;
    return content;
  };
  const decided = items.filter((scan) => Boolean(scan.decision));
  const eyebrow = !data ? "Scan decisions" : decided.length === 0 ? "No scans" : `Latest ${decided.length} scans`;
  return (
    <>
      <Panel title="Decisions" eyebrow={eyebrow} className="span-4">
        {body(
          decided.length === 0 ? (
            <EmptyState
              title="No decisions yet"
              message="No scans recorded yet. Click 'Start scan' to analyze an artifact."
              headingLevel={3}
            />
          ) : (
            <DecisionSummary scans={decided} />
          ),
        )}
      </Panel>
      <Panel title="Latest REVIEW and BLOCK findings" eyebrow="Highest CVSS first" className="span-8">
        {body(<AttentionFindings scans={items} />)}
      </Panel>
    </>
  );
}

export default function Dashboard() {
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p className="page-head__lede">Evidence, risk decisions and open questions across recent scans.</p>
        </div>
      </header>
      <div className="bento">
        <div className="span-12">
          <ScanCounts />
        </div>
        <Panel title="Recent scans" className="span-12 recent-scans">
          <RecentScans />
        </Panel>
        <LatestScanPanels />
      </div>
    </>
  );
}
