/** Helpers for the live scan progress overlay. */

export const STEPS = [
  "Initializing & resolving artifact",
  "Analyzing dependencies & lineage",
  "Evaluating ProvenanceX risk & policy",
  "Recording evidence & finalizing decision",
];

export const POLL_MS = 1800;
export const COMPLETE_HOLD_MS = 400;

const EVIDENCE_STAGES = ["graph", "vulnerabilities", "provenance"];
const hasStage = (stages, name) => Boolean(stages && stages[name]);

/**
 * Index of the active step (STEPS.length once everything is done).
 * Only steps 1 and 2 follow real data: a running scan has been picked up, and the evidence
 * stages (SBOM or AI-BOM, graph, vulnerabilities, provenance) are recorded as they finish.
 * The API does not report risk or anchoring progress, so step 3 is inferred from the evidence
 * stages and step 4 is only marked done when the scan itself completes.
 */
export function activeStep(scan) {
  if (!scan || scan.status === "queued") return 0;
  if (scan.status === "completed") return STEPS.length;
  const stages = scan.stages;
  const bom = hasStage(stages, "sbom") || hasStage(stages, "aibom");
  return bom && EVIDENCE_STAGES.every((name) => hasStage(stages, name)) ? 2 : 1;
}

/** "00:07", or "1:02:03" past an hour. */
export function formatElapsed(totalSeconds) {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const pad = (value) => String(value).padStart(2, "0");
  const hours = Math.floor(seconds / 3600);
  const rest = `${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;
  return hours ? `${hours}:${rest}` : rest;
}
