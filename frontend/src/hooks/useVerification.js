import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api } from "../services/api.js";

const IDLE = { status: "idle", result: null, error: null, job: null };
const FINISHED = new Set(["completed", "failed"]);
const ACTIVE = new Set(["queued", "running"]);
export const VERIFY_POLL_MS = 1500;
// The server fails a job past VERIFY_MAX_SECONDS (600 s by default); stop polling a bit later.
export const VERIFY_MAX_WAIT_MS = 11 * 60 * 1000;

function invalid(message) {
  return new ApiError({ code: "invalid_response", message });
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}

/** A finished job's answer, or throws when the response is not a usable job. */
function finishedResult(job) {
  if (typeof job?.result?.state !== "string") throw invalid("The verification job had no answer");
  return job.result;
}

/**
 * POST /verify queues a verification job; this hook then polls GET /verifications/{job_id}
 * until the job finishes, and only when `verify` is called.
 *
 * status: "idle" | "checking" | "done" | "failed". While checking, `job` is "queued" or
 * "running". "failed" means no verification answer was obtained (the request failed, the
 * response was invalid, or the job did not finish in time), so it stays apart from the UNKNOWN
 * state, which is a real answer. A job the server failed answers UNKNOWN with its reason.
 */
export default function useVerification(scanId, { pollMs = VERIFY_POLL_MS, maxWaitMs = VERIFY_MAX_WAIT_MS } = {}) {
  const [state, setState] = useState({ scanId, ...IDLE });
  const controllerRef = useRef(null);

  // A result belongs to one scan. Leaving that scan cancels the request and the polling.
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
    const { signal } = controller;
    controllerRef.current = controller;
    setState({ scanId, status: "checking", result: null, error: null, job: "queued" });
    try {
      let job = await api.verifyScan(scanId, { signal });
      const deadline = Date.now() + maxWaitMs;
      while (!signal.aborted) {
        if (typeof job?.job_id !== "string" || !(FINISHED.has(job.status) || ACTIVE.has(job.status))) {
          throw invalid("The verification response was not a job");
        }
        if (FINISHED.has(job.status)) {
          const result = finishedResult(job);
          setState({ scanId, status: "done", result, error: null, job: job.status });
          return;
        }
        setState((prev) => (prev.scanId === scanId ? { ...prev, job: job.status } : prev));
        if (Date.now() > deadline) {
          throw new ApiError({ code: "verify_wait_timeout", message: "The verification did not finish in time" });
        }
        await sleep(pollMs, signal);
        if (signal.aborted) return;
        job = await api.getVerification(scanId, job.job_id, { signal });
      }
    } catch (error) {
      if (!signal.aborted) setState({ scanId, status: "failed", result: null, error, job: null });
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
    }
  }, [scanId, pollMs, maxWaitMs]);

  const { status, result, error, job } = state.scanId === scanId ? state : IDLE;
  return { status, result, error, job, verify };
}
