import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

const SCAN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const isScanId = (value) => typeof value === "string" && SCAN_ID.test(value);

/** The selected scan lives in ?scan=, so a page can be linked and reloaded. */
export default function useScanSelection() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("scan");
  const scanId = isScanId(raw) ? raw : null;

  // Choosing another scan clears its filters and page.
  const selectScan = useCallback(
    (id) => setParams(id ? { scan: id } : {}),
    [setParams],
  );

  return { scanId, invalid: raw !== null && scanId === null, selectScan };
}
