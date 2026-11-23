// Per-stage scan progress, read from the stages the backend records as each one finishes
// (backend/app/pipeline/stages.py). A stage the backend has not reported is never shown as done.

export const POLL_MS = 1800;
export const COMPLETE_HOLD_MS = 400;

const FETCH = { key: "fetch", label: "Fetch and hash artifact" };
const SHARED = [
  { key: "graph", label: "Build dependency or lineage graph" },
  { key: "vulnerabilities", label: "Look up known vulnerabilities" },
  { key: "provenance", label: "Check provenance and integrity" },
  { key: "static", label: "Static analysis" },
  { key: "sandbox", label: "Sandbox behaviour analysis" },
  { key: "risk", label: "Risk score and policy decision" },
  { key: "anchor", label: "Anchor evidence on the chain" },
];

const STAGE_LISTS = {
  software: [FETCH, { key: "sbom", label: "Generate SBOM" }, ...SHARED],
  model: [FETCH, { key: "aibom", label: "Build AI-BOM" }, ...SHARED],
};

/** Display meaning of each state: words and an icon name, never colour alone. */
export const STAGE_STATES = {
  done: { label: "Done", tone: "allow" },
  partial: { label: "Partial", tone: "review" },
  skipped: { label: "Skipped", tone: "neutral" },
  unavailable: { label: "Unavailable", tone: "unknown" },
  error: { label: "Error", tone: "block" },
  active: { label: "In progress", tone: "accent" },
  pending: { label: "Waiting", tone: "neutral" },
  not_run: { label: "Not run", tone: "neutral" },
  not_reported: { label: "Not reported", tone: "unknown" },
};

const RECORDED = {
  completed: "done",
  partial: "partial",
  skipped: "skipped",
  unavailable: "unavailable",
  error: "error",
};

export function workflowKind(artifactType) {
  return artifactType === "software" || artifactType === "container" ? "software" : "model";
}

function fetchDone(scan) {
  return Boolean(scan?.artifact?.sha256 || scan?.ingest || (scan?.stages && Object.keys(scan.stages).length));
}

/**
 * One entry per stage: { key, label, state, reason, provider }.
 * - Recorded stages show the backend status.
 * - While running, only the first unrecorded stage is "in progress" (stages run in order).
 * - After a failure, unrecorded stages are "not run"; after completion, "not reported".
 */
export function stageStatuses(scan, kind = "software") {
  const list = STAGE_LISTS[kind] || STAGE_LISTS.software;
  const status = scan?.status ?? "queued";
  const recorded = scan?.stages || {};
  let activeTaken = false;
  return list.map(({ key, label }) => {
    const entry = key === "fetch" ? null : recorded[key];
    let state;
    if (key === "fetch" && fetchDone(scan)) state = "done";
    else if (entry && RECORDED[entry.status]) state = RECORDED[entry.status];
    else if (entry) state = "not_reported";
    else if (status === "completed") state = "not_reported";
    else if (status === "failed") state = "not_run";
    else if (status === "running" && !activeTaken) {
      state = "active";
      activeTaken = true;
    } else state = "pending";
    return {
      key,
      label,
      state,
      reason: entry && typeof entry.reason === "string" ? entry.reason : null,
      provider: entry && typeof entry.provider === "string" ? entry.provider : null,
    };
  });
}

/** "00:07", or "1:02:03" past an hour. */
export function formatElapsed(totalSeconds) {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const pad = (value) => String(value).padStart(2, "0");
  const hours = Math.floor(seconds / 3600);
  const rest = `${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;
  return hours ? `${hours}:${rest}` : rest;
}
