import { useCallback } from "react";
import useApi from "../../hooks/useApi.js";
import { formatDateTime } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import { api } from "../../services/api.js";
import ErrorState from "../ui/ErrorState.jsx";
import LoadingState from "../ui/LoadingState.jsx";

const PICKER_LIMIT = 100;

/** Choose one of the latest scans. Decisions stay out of the option text. */
export default function ScanPicker({ scanId, onSelect }) {
  const fetcher = useCallback((options) => api.listScans({ limit: PICKER_LIMIT, ...options }), []);
  const { status, data, error, reload } = useApi(fetcher);

  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load scans" />;
  if (!data) return <LoadingState label="Loading scans" lines={1} />;

  const items = data.items ?? [];
  const known = items.some((scan) => scan.scan_id === scanId);
  return (
    <label className="field scan-picker">
      <span className="field__label">Scan (latest {PICKER_LIMIT})</span>
      <select
        className="field__control"
        value={scanId || ""}
        onChange={(event) => onSelect(event.target.value || null)}
      >
        <option value="">Choose a scan</option>
        {scanId && !known ? <option value={scanId}>Selected scan</option> : null}
        {items.map((scan) => (
          <option key={scan.scan_id} value={scan.scan_id}>
            {sanitizeDisplay(scan.artifact.name)} · {formatDateTime(scan.created_at)}
          </option>
        ))}
      </select>
    </label>
  );
}
