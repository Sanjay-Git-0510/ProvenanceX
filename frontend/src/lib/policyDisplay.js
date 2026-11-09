// Display copies of backend policy values. A test compares ALLOW_MIN_CONFIDENCE with
// min_allow_confidence in backend/app/risk/policy_config.py, because /risk does not return it.
import { humanize } from "./format.js";

export const ALLOW_MIN_CONFIDENCE = 0.6;

export const FLIP_NOTICE = `A decision can flip between scans when confidence crosses ${ALLOW_MIN_CONFIDENCE.toFixed(2)}, even if the artifact has not changed.`;

const LAYER_LABELS = {
  vulnerability: "Vulnerability",
  provenance_integrity: "Provenance and integrity",
  graph: "Graph",
  static: "Static",
  behavioral: "Behavioral",
  ai_specific: "AI-specific",
  ml_supervised: "ML supervised",
  ml_anomaly: "ML anomaly",
};

export function layerLabel(layer) {
  return LAYER_LABELS[layer] || humanize(layer);
}
