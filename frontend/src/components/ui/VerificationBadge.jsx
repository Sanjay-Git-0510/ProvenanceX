import { CircleDashed, Link2Off, ShieldCheck } from "lucide-react";
import Badge from "./Badge.jsx";

const STATES = {
  VERIFIED: { tone: "allow", icon: ShieldCheck, note: "record unchanged" },
  MISMATCH: { tone: "block" },
  "NOT ANCHORED": { tone: "neutral", icon: Link2Off },
  UNKNOWN: { tone: "unknown" },
};

/** VERIFIED means the record is unchanged, not that the scanner was right. */
export default function VerificationBadge({ state }) {
  if (state === null || state === undefined) {
    return <Badge icon={CircleDashed}>Not checked yet</Badge>;
  }
  const label = Object.hasOwn(STATES, state) ? state : "UNKNOWN";
  const { tone, icon, note } = STATES[label];
  return (
    <Badge tone={tone} icon={icon}>
      {label}
      {note ? <span className="badge__note">· {note}</span> : null}
    </Badge>
  );
}
