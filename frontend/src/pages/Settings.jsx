import Badge from "../components/ui/Badge.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import LoadingState from "../components/ui/LoadingState.jsx";
import Panel from "../components/ui/Panel.jsx";
import useHealth from "../hooks/useHealth.js";
import { NOT_AVAILABLE } from "../lib/format.js";
import { sanitizeDisplay } from "../lib/sanitizeDisplay.js";

const STATUS = {
  ok: { api: ["allow", "Reachable"], db: ["allow", "Ready"] },
  degraded: { api: ["allow", "Reachable"], db: ["block", "Not ready"] },
  down: { api: ["block", "Unreachable"], db: ["unknown", "Unknown: the API did not answer"] },
};

function StatusRow({ label, status: [tone, text] }) {
  return (
    <div className="dl__row">
      <dt>{label}</dt>
      <dd>
        <Badge tone={tone}>{text}</Badge>
      </dd>
    </div>
  );
}

function Health() {
  const { status, version, error } = useHealth();
  if (status === "loading") return <LoadingState label="Checking the API" lines={2} />;
  const row = STATUS[status];
  return (
    <>
      <dl className="dl">
        <StatusRow label="API" status={row.api} />
        <StatusRow label="Database" status={row.db} />
        <div className="dl__row">
          <dt>Scanner version</dt>
          <dd>{version ? sanitizeDisplay(version) : NOT_AVAILABLE}</dd>
        </div>
      </dl>
      {status !== "ok" ? (
        <div className="panel__section">
          <ErrorState error={error} headingLevel={3} title="Latest health check failed" />
        </div>
      ) : null}
    </>
  );
}

export default function Settings() {
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="page-head__lede">Read-only. Configuration is set through environment variables on the server.</p>
        </div>
      </header>
      <div className="bento">
        <Panel title="System health" className="span-6">
          <Health />
        </Panel>
      </div>
    </>
  );
}
