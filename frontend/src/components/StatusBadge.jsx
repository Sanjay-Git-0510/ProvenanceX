import useHealth from "../hooks/useHealth.js";

// Text labels carry the meaning; color is only a secondary cue.
const LABELS = {
  loading: "CHECKING",
  ok: "API OK · DB OK",
  degraded: "API OK · DB UNAVAILABLE",
  down: "API UNREACHABLE",
};

export default function StatusBadge() {
  const { status, version, error } = useHealth();
  return (
    <span
      className={`status-badge status-${status}`}
      role="status"
      title={error ? `${error.code}: ${error.message}` : undefined}
    >
      {LABELS[status]}
      {version ? ` · v${version}` : ""}
    </span>
  );
}
