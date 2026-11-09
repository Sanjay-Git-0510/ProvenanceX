import { useCallback } from "react";
import useApi from "../../hooks/useApi.js";
import { formatCount } from "../../lib/format.js";
import { api } from "../../services/api.js";
import ErrorState from "../ui/ErrorState.jsx";
import LoadingState from "../ui/LoadingState.jsx";
import ScanStatusBadge from "./ScanStatusBadge.jsx";

const STATUSES = ["queued", "running", "completed", "failed"];

/** True totals for every status, read from each filtered list's page total. */
export default function ScanCounts() {
  const fetcher = useCallback(async ({ signal }) => {
    const pages = await Promise.all(STATUSES.map((status) => api.listScans({ status, limit: 1, signal })));
    return pages.map((page) => page.page?.total ?? 0);
  }, []);
  const { status, data, error, reload } = useApi(fetcher);

  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load scan counts" />;
  if (!data) return <LoadingState label="Loading scan counts" lines={1} />;
  return (
    <ul className="count-strip">
      {STATUSES.map((name, index) => (
        <li key={name}>
          <span className="count-strip__value">{formatCount(data[index])}</span>
          <ScanStatusBadge status={name} />
        </li>
      ))}
    </ul>
  );
}
