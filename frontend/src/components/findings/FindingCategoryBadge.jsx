import { Bug, Code, Radar, ShieldQuestionMark } from "lucide-react";
import { humanize } from "../../lib/format.js";
import Badge from "../ui/Badge.jsx";

// Known vulnerabilities use the accent tone; suspicious signals stay neutral with their own icons.
const CATEGORIES = {
  vulnerability: { label: "Known vulnerability", tone: "accent", icon: Bug },
  static: { label: "Suspicious: static", tone: "neutral", icon: Code },
  behavioral: { label: "Suspicious: behavioral", tone: "neutral", icon: Radar },
  provenance: { label: "Provenance signal", tone: "neutral", icon: ShieldQuestionMark },
};

export const CATEGORY_NAMES = Object.keys(CATEGORIES);

export function categoryLabel(category) {
  return CATEGORIES[category]?.label || humanize(category);
}

export default function FindingCategoryBadge({ category }) {
  const entry = CATEGORIES[category];
  if (!entry) return <Badge tone="unknown">{humanize(category)}</Badge>;
  return (
    <Badge tone={entry.tone} icon={entry.icon}>
      {entry.label}
    </Badge>
  );
}

const SEVERITY_TONES = { CRITICAL: "block", HIGH: "block", MEDIUM: "review", LOW: "neutral" };

export function SeverityBadge({ severity }) {
  const known = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].includes(severity);
  return <Badge tone={SEVERITY_TONES[severity] || "unknown"}>{known ? severity : "UNKNOWN"}</Badge>;
}
