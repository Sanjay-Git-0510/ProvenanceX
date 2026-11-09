import { CircleDashed } from "lucide-react";
import { NOT_COMPUTED } from "../../lib/format.js";
import Badge from "./Badge.jsx";

const TONES = { ALLOW: "allow", REVIEW: "review", BLOCK: "block" };

/** A null decision is "Not computed yet". An unrecognized value is UNKNOWN, never ALLOW. */
export default function DecisionBadge({ decision }) {
  if (decision === null || decision === undefined) {
    return <Badge icon={CircleDashed}>{NOT_COMPUTED}</Badge>;
  }
  const tone = Object.hasOwn(TONES, decision) ? TONES[decision] : null;
  return tone ? <Badge tone={tone}>{decision}</Badge> : <Badge tone="unknown">UNKNOWN</Badge>;
}
