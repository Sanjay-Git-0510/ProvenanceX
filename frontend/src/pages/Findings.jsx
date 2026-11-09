import { useSearchParams } from "react-router-dom";
import EmptyState from "../components/EmptyState.jsx";
import FindingFilters, { SEVERITIES, SOURCES } from "../components/findings/FindingFilters.jsx";
import FindingsTable, { FindingsEmpty } from "../components/findings/FindingsTable.jsx";
import { CATEGORY_NAMES } from "../components/findings/FindingCategoryBadge.jsx";
import ScanPicker from "../components/scan/ScanPicker.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import LoadingState from "../components/ui/LoadingState.jsx";
import MockLabel from "../components/ui/MockLabel.jsx";
import Pagination from "../components/ui/Pagination.jsx";
import Panel from "../components/ui/Panel.jsx";
import useFindings from "../hooks/useFindings.js";
import useScanSelection from "../hooks/useScanSelection.js";

const PAGE_SIZE = 50;

const allowed = (value, options) => (options.includes(value) ? value : undefined);

/** Only recognized values from the URL reach the API. */
function readFilters(params) {
  const offset = Number.parseInt(params.get("offset") ?? "0", 10);
  return {
    category: allowed(params.get("category"), CATEGORY_NAMES),
    severity: allowed(params.get("severity"), SEVERITIES),
    source: allowed(params.get("source"), SOURCES),
    offset: Number.isSafeInteger(offset) && offset > 0 ? offset : 0,
  };
}

function Results({ scanId, filters, onPage }) {
  const { status, data, error, reload } = useFindings(scanId, { ...filters, limit: PAGE_SIZE });
  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load findings" headingLevel={3} />;
  if (!data) return <LoadingState label="Loading findings" />;
  const filtered = Boolean(filters.category || filters.severity || filters.source);
  return (
    <>
      {data.contains_mock ? (
        <p className="notice__badges">
          <MockLabel isMock>THIS SCAN CONTAINS MOCK FINDINGS</MockLabel>
        </p>
      ) : null}
      <FindingsTable
        caption="Findings, highest CVSS first"
        findings={data.items ?? []}
        empty={<FindingsEmpty stages={data.stages} category={filters.category} filtered={filtered} />}
      />
      <Pagination label="Findings pages" total={data.total} limit={data.limit} offset={data.offset} onChange={onPage} />
    </>
  );
}

export default function Findings() {
  const { scanId, invalid, selectScan } = useScanSelection();
  const [params, setParams] = useSearchParams();
  const filters = readFilters(params);

  function update(changes) {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([key, value]) => {
      if (value) next.set(key, String(value));
      else next.delete(key);
    });
    setParams(next);
  }

  return (
    <>
      <header className="page-head">
        <div>
          <h1>Findings</h1>
          <p className="page-head__lede">
            A known vulnerability is an advisory match, not evidence of malice. A suspicious signal shows what code can
            do, not what it did.
          </p>
        </div>
      </header>
      <div className="toolbar">
        <ScanPicker scanId={scanId} onSelect={selectScan} />
        {scanId ? (
          <FindingFilters filters={filters} onChange={(name, value) => update({ [name]: value, offset: null })} />
        ) : null}
      </div>
      {invalid ? (
        <EmptyState title="Not a valid scan ID" message="Choose a scan from the list." headingLevel={2} />
      ) : null}
      {!scanId && !invalid ? (
        <EmptyState title="Choose a scan" message="Findings are listed per scan." headingLevel={2} />
      ) : null}
      {scanId ? (
        <Panel title="Findings">
          <Results scanId={scanId} filters={filters} onPage={(offset) => update({ offset })} />
        </Panel>
      ) : null}
    </>
  );
}
