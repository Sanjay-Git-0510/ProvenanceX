import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Load data from one API call and cancel it when it goes stale.
 *
 * `fetcher` receives `{ signal }`. Wrap it in useCallback: a new function means a new request.
 * Pass null to wait. Data from a different fetcher is cleared, so one scan never shows another's.
 * status: "idle" | "loading" | "success" | "error".
 */
export default function useApi(fetcher) {
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

  const reload = useCallback(() => setAttempt((value) => value + 1), []);
  return { ...state, reload };
}
