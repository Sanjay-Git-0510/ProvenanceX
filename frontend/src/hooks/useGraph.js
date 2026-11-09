import { useCallback, useMemo } from "react";
import { normalizeGraph } from "../lib/graphLayout.js";
import { api } from "../services/api.js";
import useApi from "./useApi.js";

/** A scan's graph, plus `graph`: its nodes and edges with only named, sanitized fields. */
export default function useGraph(scanId) {
  const fetcher = useCallback((options) => api.getGraph(scanId, options), [scanId]);
  const result = useApi(scanId ? fetcher : null);
  const graph = useMemo(() => (result.data ? normalizeGraph(result.data) : null), [result.data]);
  return { ...result, graph };
}
