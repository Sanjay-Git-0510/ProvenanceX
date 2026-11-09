import { CircleCheck, CircleX, Clock, Play } from "lucide-react";
import Badge from "../ui/Badge.jsx";

const STATES = {
  queued: { label: "Queued", tone: "neutral", icon: Clock },
  running: { label: "Running", tone: "accent", icon: Play },
  completed: { label: "Completed", tone: "neutral", icon: CircleCheck },
  failed: { label: "Failed", tone: "block", icon: CircleX },
};

export default function ScanStatusBadge({ status }) {
  const state = STATES[status];
  if (!state) return <Badge tone="unknown">Unknown status</Badge>;
  return (
    <Badge tone={state.tone} icon={state.icon}>
      {state.label}
    </Badge>
  );
}
