// Display meaning of backend evidence states (backend/app/risk/evidence_status.py).
// Each state has words and an icon so meaning never relies on colour. Only confirmed
// tampering and dangerous behaviour are confirmed; everything else is a signal or a gap.
import {
  Bug,
  CircleDashed,
  CircleQuestionMark,
  FileQuestionMark,
  History,
  ShieldAlert,
  Siren,
} from "lucide-react";
import { humanize } from "./format.js";

export const EVIDENCE_STATES = {
  confirmed_tampering: { label: "Confirmed tampering", kind: "confirmed", tone: "block", icon: ShieldAlert },
  dangerous_behavior: {
    label: "Dangerous behaviour (not proof of intent)",
    kind: "confirmed",
    tone: "block",
    icon: Siren,
  },
  known_vulnerability: { label: "Known vulnerability", kind: "signal", tone: "review", icon: Bug },
  weak_provenance: { label: "Weak provenance", kind: "gap", tone: "unknown", icon: FileQuestionMark },
  integrity_unverified: { label: "Integrity not checked", kind: "gap", tone: "unknown", icon: CircleQuestionMark },
  no_prior_scan: { label: "No prior scan", kind: "gap", tone: "unknown", icon: History },
  missing_evidence: { label: "Missing evidence", kind: "gap", tone: "unknown", icon: CircleDashed },
};

export const KIND_LABELS = {
  confirmed: "Confirmed",
  signal: "Signal",
  gap: "Gap",
};

/** Unknown states are shown as unconfirmed gaps, never as confirmed. */
export function evidenceMeta(state) {
  if (Object.hasOwn(EVIDENCE_STATES, state)) return EVIDENCE_STATES[state];
  return { label: humanize(state) || "Unknown", kind: "gap", tone: "unknown", icon: CircleQuestionMark };
}

export const RISK_LEVELS = new Set(["LOW", "MEDIUM", "HIGH"]);

/** A summary from an earlier policy, which recorded no evidence status (pre-v2 result). */
export function isLegacySummary(summary) {
  return Boolean(summary && summary.confirmed_evidence === null);
}
