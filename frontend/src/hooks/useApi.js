import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Load data from one API call and cancel it when it goes stale.
 *
 * `fetcher` receives `{ signal }`. Wrap it in useCallback: a new function means a new request.
 * Pass null to wait. Data from a different fetcher is cleared, so one scan never shows another's.
 * pollMs > 0 refetches on that interval while the tab is visible, keeping the old data on screen.
 * status: "idle" | "loading" | "success" | "error".
 */
export default function useApi(fetcher, { pollMs = 0 } = {}) {
  const [state, setState] = useState({
    status: fetcher ? "loading" : "idle",
    data: null,
    error: null,
  });
  const [attempt, setAttempt] = useState(0);
  const lastFetcher = useRef(fetcher);

  useEffect(() => {
    const sameFetcher = lastFetcher.current === fetcher;
    lastFetcher.current = fetcher;
    if (!fetcher) {
      setState({ status: "idle", data: null, error: null });
      return undefined;
    }

    const controller = new AbortController();
    setState((prev) => ({
      status: "loading",
      data: sameFetcher ? prev.data : null,
      error: null,
    }));
    fetcher({ signal: controller.signal }).then(
      (data) => {
        if (!controller.signal.aborted) setState({ status: "success", data, error: null });
      },
      (error) => {
        if (!controller.signal.aborted) setState({ status: "error", data: null, error });
      },
    );
    return () => controller.abort();
  }, [fetcher, attempt]);

  useEffect(() => {
    if (!fetcher || !pollMs) return undefined;
    const timer = setInterval(() => {
      if (document.visibilityState !== "hidden") setAttempt((value) => value + 1);
    }, pollMs);
    return () => clearInterval(timer);
  }, [fetcher, pollMs]);

  const reload = useCallback(() => setAttempt((value) => value + 1), []);
  return { ...state, reload };
}
