import { useCallback } from "react";
import { api } from "../services/api.js";
import useApi from "./useApi.js";

/** One page of findings for a scan. Filters are applied by the API. */
export default function useFindings(scanId, { category, severity, source, limit, offset } = {}) {
  const fetcher = useCallback(
    (options) => api.getFindings(scanId, { category, severity, source, limit, offset, ...options }),
    [scanId, category, severity, source, limit, offset],
  );
  return useApi(scanId ? fetcher : null);
}
