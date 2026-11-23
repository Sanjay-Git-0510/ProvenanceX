import { RISK_LEVELS } from "../../lib/evidenceStatus.js";
import Badge from "../ui/Badge.jsx";

const TONES = { LOW: "allow", MEDIUM: "review", HIGH: "block" };

/** The backend's LOW/MEDIUM/HIGH band of the score, always as words. Missing is said so. */
export default function RiskLevelBadge({ level }) {
  if (!RISK_LEVELS.has(level)) return <Badge tone="unknown">NO RISK LEVEL</Badge>;
  return <Badge tone={TONES[level]}>{level} RISK</Badge>;
}
