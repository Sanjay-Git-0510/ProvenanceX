import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api.js";

export const POLL_MS = 3000;
const TERMINAL = new Set(["completed", "failed"]);

export const isTerminal = (status) => TERMINAL.has(status);

/**
 * Follow one scan through the sanitized /evidence summary.
 * Polls until the scan finishes, pauses while the tab is hidden and refreshes when it returns.
 * A failed poll stops polling and reports the error, so `reload` is the way to resume.
 */
export default function useScan(scanId, { pollMs = POLL_MS } = {}) {
  const [state, setState] = useState({ status: scanId ? "loading" : "idle", data: null, error: null });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!scanId) {
      setState({ status: "idle", data: null, error: null });
      return undefined;
    }
    setState({ status: "loading", data: null, error: null });

    let stopped = false;
    let timer = null;
    let controller = null;

    function schedule() {
      clearTimeout(timer);
      if (!stopped && !document.hidden) timer = setTimeout(load, pollMs);
    }

    async function load() {
      clearTimeout(timer);
      controller?.abort();
      const current = new AbortController();
      controller = current;
      try {
        const data = await api.getEvidence(scanId, {
          findingsLimit: 1,
          componentsLimit: 1,
          signal: current.signal,
        });
        if (current.signal.aborted) return;
        if (isTerminal(data.scan_status)) stopped = true;
        setState({ status: "success", data, error: null });
        schedule();
      } catch (error) {
        if (current.signal.aborted) return;
        stopped = true;
        setState({ status: "error", data: null, error });
      }
    }

    function onVisibilityChange() {
      if (document.hidden) {
        clearTimeout(timer);
      } else if (!stopped) {
        load();
      }
    }

    load();
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      stopped = true;
      clearTimeout(timer);
      controller?.abort();
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [scanId, pollMs, attempt]);

  const reload = useCallback(() => setAttempt((value) => value + 1), []);
  return { ...state, reload };
}
