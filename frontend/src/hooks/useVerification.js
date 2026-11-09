import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api } from "../services/api.js";

const IDLE = { status: "idle", result: null, error: null };

/**
 * Runs POST /verify only when `verify` is called.
 *
 * status: "idle" | "checking" | "done" | "failed". "failed" means the request did not produce a
 * verification answer, so it is kept apart from the UNKNOWN state, which is a real answer.
 */
export default function useVerification(scanId) {
  const [state, setState] = useState({ scanId, ...IDLE });
  const controllerRef = useRef(null);

  // A result belongs to one scan. Leaving that scan cancels the request.
  useEffect(
    () => () => {
      controllerRef.current?.abort();
      controllerRef.current = null;
    },
    [scanId],
  );

  const verify = useCallback(async () => {
    if (!scanId || controllerRef.current) return;
    const controller = new AbortController();
    controllerRef.current = controller;
    setState({ scanId, status: "checking", result: null, error: null });
    try {
      const result = await api.verifyScan(scanId, { signal: controller.signal });
      if (controller.signal.aborted) return;
      if (typeof result?.state !== "string") {
        throw new ApiError({ code: "invalid_response", message: "The verification response had no state" });
      }
      setState({ scanId, status: "done", result, error: null });
    } catch (error) {
      if (!controller.signal.aborted) setState({ scanId, status: "failed", result: null, error });
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  }, [scanId]);

  const { status, result, error } = state.scanId === scanId ? state : IDLE;
  return { status, result, error, verify };
}
