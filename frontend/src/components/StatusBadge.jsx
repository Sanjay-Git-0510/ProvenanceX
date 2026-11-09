import { CircleCheck, CircleX, Clock, TriangleAlert } from "lucide-react";
import useHealth from "../hooks/useHealth.js";
import { sanitizeDisplay } from "../lib/sanitizeDisplay.js";

// Text labels carry the meaning; colour is only a secondary cue.
const STATES = {
  loading: { label: "CHECKING", icon: Clock },
  ok: { label: "API OK · DB OK", icon: CircleCheck },
  degraded: { label: "API OK · DB UNAVAILABLE", icon: TriangleAlert },
  down: { label: "API UNREACHABLE", icon: CircleX },
};

export default function StatusBadge() {
  const { status, version, error } = useHealth();
  const { label, icon: Icon } = STATES[status];
  return (
    <span
      className={`chip glass chip--${status}`}
      role="status"
      title={error ? sanitizeDisplay(`${error.code}: ${error.message}`) : undefined}
    >
      <Icon size={14} aria-hidden="true" />
      <span>
        {label}
        {version ? <span className="hide-below-sm"> · v{version}</span> : null}
      </span>
    </span>
  );
}
